/*
 * Copyright 2019 University of Washington, Max Planck Institute for
 * Software Systems, and The University of Texas at Austin
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>

#include <utils.h>
#include <utils_rng.h>

#include "../common/socket_shim.h"
#include "../common/microbench.h"

//#define PRINT_STATS
//#define PRINT_TSS
#ifdef PRINT_STATS
#   define STATS_ADD(c, f, n) __sync_fetch_and_add(&c->f, n)
#   define STATS_TS(n) uint64_t n = get_nanos()
#else
#   define STATS_ADD(c, f, n) do { } while (0)
#   define STATS_TS(n) do { } while (0)
#endif

extern uint64_t icache_fill1(uint64_t x);
extern uint64_t icache_fill8(uint64_t x);
extern uint64_t icache_fill64(uint64_t x);
extern uint64_t icache_fill256(uint64_t x);
extern uint64_t icache_fill512(uint64_t x);

static uint32_t listen_backlog = 512;
static uint32_t max_events = 128;
static uint32_t max_flows = 4096;
static uint32_t max_bytes = 1024;
static uint32_t op_delay = 0;
static uint32_t working_set = 0;
static uint32_t icache_set = 0;
static uint32_t icache_block = 0;
static uint16_t listen_port;
static volatile uint32_t num_ready = 0;

struct connection {
    int fd;
    int len;
    int off;
    int ep_write;
    struct connection *next;
    char buf[];
};

struct core {
    int cn;
    int lfd;
    int ep;
    uint32_t opaque;
    ssctx_t sc;
    struct utils_rng rng;
    uint8_t *workingset;
    struct connection *conns;
    uint32_t num_conns;
#ifdef PRINT_STATS
    uint64_t rx_calls;
    uint64_t rx_fail;
    uint64_t rx_cycles;
    uint64_t rx_bytes;
    uint64_t tx_calls;
    uint64_t tx_fail;
    uint64_t tx_cycles;
    uint64_t tx_bytes;
    uint64_t *epoll_hist;
#endif
} __attribute__((aligned((64))));

enum rx_result {
  RX_SUCCESS = 0,
  RX_FAIL,
  RX_RETRY,
  RX_EOS,
};

static inline uint64_t get_nanos(void)
{
#ifdef PRINT_TSS
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 * 1000 * 1000 + ts.tv_nsec;
#else
    return 0;
#endif
}

#ifdef PRINT_STATS
static inline uint64_t read_cnt(uint64_t *p)
{
  uint64_t v = *p;
  __sync_fetch_and_sub(p, v);
  return v;
}
#endif

static int open_listening(ssctx_t sc, int cn)
{
    int fd, ret;
    struct sockaddr_in si;

    if ((fd = ss_socket(sc, AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        fprintf(stderr, "[%d] socket failed\n", cn);
        abort();
    }

    /* set reuse port (for linux to open multiple listening sockets) */
    if (ss_set_reuseport(sc, fd) != 0) {
        fprintf(stderr, "[%d] set reuseport failed\n", cn);
        abort();
    }

    /* set non blocking */
    if ((ret = ss_set_nonblock(sc, fd)) < 0) {
        fprintf(stderr, "[%d] setsock_nonblock failed: %d\n", cn, ret);
        abort();
    }

    memset(&si, 0, sizeof(si));
    si.sin_family = AF_INET;
    si.sin_port = htons(listen_port);

    /* bind socket */
    if ((ret = ss_bind(sc, fd, (struct sockaddr *) &si, sizeof(si)))
            < 0)
    {
        fprintf(stderr, "[%d] bind failed: %d\n", cn, ret);
        abort();
    }

    /* listen on socket */
    if ((ret = ss_listen(sc, fd, listen_backlog)) < 0) {
        fprintf(stderr, "[%d] listen failed: %d\n", cn, ret);
        abort();
    }

    return fd;
}

static void prepare_core(struct core *c)
{
    int i, cn = c->cn;
    ss_epev_t ev;
    struct connection *co;
#ifdef USE_MTCP
    int ret;
#endif

#ifdef PRINT_STATS
    if ((c->epoll_hist = calloc(max_flows + 2, sizeof(*c->epoll_hist)))
        == NULL)
    {
      fprintf(stderr, "[%d] calloc for epoll_hist failed\n", cn);
      abort();
    }
#endif

#ifdef USE_MTCP
    /* get mtcp context ready */
    if ((ret = mtcp_core_affinitize(cn)) != 0) {
        fprintf(stderr, "[%d] mtcp_core_affinitize failed: %d\n", cn, ret);
        abort();
    }

    if ((c->sc = mtcp_create_context(cn)) == NULL) {
        fprintf(stderr, "[%d] mtcp_create_context failed\n", cn);
        abort();
    }
#endif

    if (working_set > 0) {
        if ((c->workingset = malloc(working_set)) == NULL) {
            fprintf(stderr, "[%d] working set alloc failed\n", cn);
            abort();
        }
    } else {
        c->workingset = NULL;
    }

    /* prepare listening socket */
    c->lfd = open_listening(c->sc, cn);

    /* prepare epoll */
    if ((c->ep = ss_epoll_create(c->sc, max_flows + 1)) < 0) {
        fprintf(stderr, "[%d] epoll_create failed\n", cn);
        abort();
    }

    /* add listening socket to epoll */
    ev.events = SS_EPOLLIN | SS_EPOLLERR | SS_EPOLLHUP;
    ev.data.ptr = NULL;
    if (ss_epoll_ctl(c->sc, c->ep, SS_EPOLL_CTL_ADD, c->lfd, &ev) < 0) {
        fprintf(stderr, "[%d] mtcp_epoll_ctl\n", cn);
        abort();
    }


    c->conns = NULL;
    for (i = 0; i < max_flows; i++) {
        /* allocate connection structs */
        if ((co = calloc(1, sizeof(*co) + max_bytes)) == NULL) {
            fprintf(stderr, "[%d] alloc of connection structs failed\n", cn);
            abort();
        }

        co->next = c->conns;
        c->conns = co;
        c->num_conns++;
    }
}

static inline void accept_connections(struct core *co)
{
    int cfd;
    struct connection *c;
    ss_epev_t ev;

    while (co->conns != NULL) {
        if ((cfd = ss_accept(co->sc, co->lfd, NULL, NULL)) < 0) {
            if (errno == EAGAIN) {
                break;
            }
            perror("accept failed");

            fprintf(stderr, "[%d] accept failed: %d\n", co->cn, cfd);
            abort();
        }

        if (ss_set_nonblock(co->sc, cfd) < 0) {
            fprintf(stderr, "[%d] set nonblock failed\n", co->cn);
            abort();
        }

        if (ss_set_nonagle(co->sc, cfd) < 0) {
            fprintf(stderr, "[%d] set nonagle failed\n", co->cn);
            abort();
        }

        c = co->conns;
        co->conns = c->next;
        co->num_conns--;

        /* add socket to epoll */
        ev.data.ptr = c;
        ev.events = SS_EPOLLIN | SS_EPOLLERR | SS_EPOLLHUP;
        if (ss_epoll_ctl(co->sc, co->ep, SS_EPOLL_CTL_ADD, cfd, &ev) < 0) {
            fprintf(stderr, "[%d] epoll_ctl CA\n", co->cn);
            abort();
        }

        c->fd = cfd;
        c->len = 0;
        c->off = 0;
        c->ep_write = 0;
    }
}

static inline void conn_epupdate(struct core *co, struct connection *c,
        int write)
{
    ss_epev_t ev;

    if (c->ep_write == write) {
        return;
    }

    /* more to send but would block */
    ev.data.ptr = c;
    ev.events = (write ? SS_EPOLLOUT : SS_EPOLLIN) | SS_EPOLLERR | SS_EPOLLHUP;
    if (ss_epoll_ctl(co->sc, co->ep, SS_EPOLL_CTL_MOD, c->fd, &ev) < 0) {
        fprintf(stderr, "[%d] epoll_ctl CM\n", co->cn);
        abort();
    }

    c->ep_write = write;
}

static inline int conn_send(struct core *co, struct connection *c)
{
    int ret;

    while (c->off < c->len) {
        STATS_ADD(co, tx_calls, 1);
        STATS_TS(tsc);
        ret = ss_write(co->sc, c->fd, c->buf + c->off, c->len - c->off);
        STATS_ADD(co, tx_cycles, get_nanos() - tsc);
        if (ret < 0 && errno == EAGAIN) {
            STATS_ADD(co, tx_fail, 1);
            return 1;
        } else if (ret < 0) {
            fprintf(stderr, "[%d] write failed\n", co->cn);
            return -1;
        }
        STATS_ADD(co, tx_bytes, ret);
        //printf("[%d] Sent %d off=%d len=%d\n", c->fd, ret, c->off, c->len);
        c->off += ret;
    }

    c->off = 0;
    c->len = 0;
    return 0;
}

static inline enum rx_result conn_recv(struct core *co, struct connection *c)
{
    int ret;

    while (c->len < max_bytes) {
        STATS_ADD(co, rx_calls, 1);
        STATS_TS(tsc);
        ret = ss_read(co->sc, c->fd, c->buf + c->len, max_bytes - c->len);
        STATS_ADD(co, rx_cycles, get_nanos() - tsc);
        if (ret < 0 && errno == EAGAIN) {
            STATS_ADD(co, rx_fail, 1);
            return RX_RETRY;
        } else if (ret < 0) {
            fprintf(stderr, "[%d] closing connection ER\n", co->cn);
            return RX_FAIL;
        } else if (ret == 0) {
            return RX_EOS;
        }
        STATS_ADD(co, rx_bytes, ret);
        c->len += ret;
    }

    c->off = 0;
    return RX_SUCCESS;
}

static inline void conn_close(struct core *co, struct connection *c)
{
    ss_close(co->sc, c->fd);
    c->next = co->conns;
    co->conns = c;
    co->num_conns++;
}

static void *thread_run(void *arg)
{
    struct core *co = arg;
    int ret, n, i, cn;
    uint32_t off;
    ss_epev_t *evs;
    struct connection *c;

    cn = co->cn;
    prepare_core(co);

    evs = calloc(max_events, sizeof(*evs));
    if (evs == NULL) {
        fprintf(stderr, "Allocating event buffer failed\n");
        abort();
    }

    __sync_fetch_and_add(&num_ready, 1);
    printf("[%d] Starting event loop\n", cn);
    while (1) {
        if ((n = ss_epoll_wait(co->sc, co->ep, evs, max_events, -1)) < 0) {
            abort();
        }
#ifdef PRINT_STATS
        STATS_ADD(co, epoll_hist[n], 1);
#endif
        for (i = 0; i < n; i++) {
            c = evs[i].data.ptr;
            if (c != NULL)
                util_prefetch0(c);
        }

        for (i = 0; i < n; i++) {
            c = evs[i].data.ptr;
            if (c == NULL) {
                /* the listening socket */
                if ((evs[i].events != SS_EPOLLIN)) {
                    fprintf(stderr, "Error on listening socket\n");
                    abort();
                }

                accept_connections(co);
            } else {
                /* connection */
                if ((evs[i].events & ~(SS_EPOLLIN | SS_EPOLLOUT))) {
                    fprintf(stderr, "Closing connection on EP error\n");
                    conn_close(co, c);
                    continue;
                }

                /* send out remaining buffer contents */
                if (c->ep_write) {
                    assert(c->len == max_bytes);
                    assert(c->off < c->len);

                    ret = conn_send(co, c);
                    if (ret != 0) {
                        /* response was not sent completely */

                        if (ret < 0) {
                            /* error, close connection */
                            fprintf(stderr, "[%d] closing connection E\n", cn);
                            conn_close(co, c);
                        }
                        continue;
                    }
                }

                /* receive request */
                ret = conn_recv(co, c);
                if (ret == RX_FAIL) {
                    /* error, close connection */
                    fprintf(stderr, "[%d] closing connection E\n", cn);
                    conn_close(co, c);
                    continue;
                } else if (ret == RX_RETRY) {
                    /* request was not received completely */
                    conn_epupdate(co, c, 0);
                    continue;
                } else if (ret == RX_EOS) {
                    /* connection shut down */
                    conn_close(co, c);
                    continue;
                }

                /* we have a complete request */
                if (op_delay > 0) {
                    co->opaque = kill_cycles(op_delay, co->opaque);
                }
                if (co->workingset != NULL) {
                    off = (utils_rng_gen32(&co->rng) % working_set) & ~63;
                    c->buf[0] = (*((volatile uint32_t *) (co->workingset + off)))++;
                }

                if (icache_block != 0) {
                    off = utils_rng_gen32(&co->rng) % icache_set;
                    if (icache_block == 1) {
                        c->buf[0] += icache_fill1(off);
                    } else if (icache_block == 8) {
                        c->buf[0] += icache_fill8(off);
                    } else if (icache_block == 64) {
                        c->buf[0] += icache_fill64(off);
                    } else if (icache_block == 256) {
                        c->buf[0] += icache_fill256(off);
                    } else if (icache_block == 512) {
                        c->buf[0] += icache_fill512(off);
                    } else {
                      fprintf(stderr, "unsupported icache block size\n");
                      abort();
                    }
                }

                /* send out response */
                assert(c->len == max_bytes);
                assert(c->off < c->len);
                ret = conn_send(co, c);
                if (ret != 0) {
                    /* response was not sent completely */

                    if (ret < 0) {
                        /* error, close connection */
                        fprintf(stderr, "[%d] closing connection E\n", cn);
                        conn_close(co, c);
                    }

                    conn_epupdate(co, c, 1);
                    continue;
                }

                /* we sent out the whole response */
                conn_epupdate(co, c, 0);
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    unsigned num_threads, i;
    struct core *cs;
    pthread_t *pts;
    char name[17];
    char *end;
#ifdef PRINT_STATS
    unsigned j;
    uint64_t x;
#endif
#ifdef USE_MTCP
    int ret;
#endif

    if (argc < 4 || argc > 11) {
        fprintf(stderr, "Usage: ./echoserver PORT THREADS CONFIG [MAX-FLOWS] "
            "[MAX-BYTES] [OP-DELAY] [WORKING-SET] [ICACHE-SET] "
            "[LISTEN-BACKLOG] [MAX-EPEVENTS]\n");
        return EXIT_FAILURE;
    }
    listen_port = atoi(argv[1]);
    num_threads = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);


#ifdef USE_MTCP
    if ((ret = mtcp_init(argv[3])) != 0) {
        fprintf(stderr, "mtcp_init failed: %d\n", ret);
        return EXIT_FAILURE;
    }
#endif

    if (argc >= 5) {
        max_flows = atoi(argv[4]);
    }
    if (argc >= 6) {
        max_bytes = atoi(argv[5]);
    }
    if (argc >= 7) {
        op_delay = atoi(argv[6]);
    }
    if (argc >= 8) {
        working_set = atoi(argv[7]);
    }
    if (argc >= 9) {
        if ((end = strchr(argv[8], ',')) == NULL) {
            return EXIT_FAILURE;
        }
        *end = 0;
        icache_block = atoi(argv[8]);
        icache_set = atoi(end + 1);
    }
    if (argc >= 10) {
        listen_backlog = atoi(argv[9]);
    }
    if (argc >= 11) {
        max_events = atoi(argv[10]);
    }

    pts = calloc(num_threads, sizeof(*pts));
    cs = calloc(num_threads, sizeof(*cs));
    if (pts == NULL || cs == NULL) {
        fprintf(stderr, "allocating thread handles failed\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < num_threads; i++) {
        cs[i].cn = i;
        if (pthread_create(pts + i, NULL, thread_run, cs + i)) {
            fprintf(stderr, "pthread_create failed\n");
            return EXIT_FAILURE;
        }

        snprintf(name, sizeof(name), "echo-w%u", i);
        pthread_setname_np(pts[i], name);
    }

    while (num_ready < num_threads);
    printf("Workers ready\n");
    fflush(stdout);

    while (1) {
        sleep(1);
#ifdef PRINT_STATS
        for (i = 0; i < num_threads; i++) {
            uint64_t rx_calls = read_cnt(&cs[i].rx_calls);
            uint64_t rx_cycles = read_cnt(&cs[i].rx_cycles);
            uint64_t tx_calls = read_cnt(&cs[i].tx_calls);
            uint64_t tx_cycles = read_cnt(&cs[i].tx_cycles);
            uint64_t rxc = (rx_calls == 0 ? 0 : rx_cycles / rx_calls);
            uint64_t txc = (tx_calls == 0 ? 0 : tx_cycles / tx_calls);
            printf("    core %2d: (rt=%"PRIu64", rf=%"PRIu64 ", rxc=%"PRIu64
                    ", rb=%"PRIu64", tt=%"PRIu64", tf=%"PRIu64", txc=%"PRIu64
                    ", tb=%"PRIu64", )", i,
                rx_calls, read_cnt(&cs[i].rx_fail), rxc,
                read_cnt(&cs[i].rx_bytes),
                tx_calls, read_cnt(&cs[i].tx_fail), txc,
                read_cnt(&cs[i].tx_bytes));
            for (j = 0; j < max_flows + 2; j++) {
              if ((x = read_cnt(&cs[i].epoll_hist[j])) != 0) {
                printf(" epoll[%u]=%"PRIu64, j, x);
              }
            }
            printf("\n");
        }

#ifdef FLEXTCP_STATS
        flextcp_stats_dump();
#endif
#endif

    }

#ifdef USE_MTCP
    mtcp_destroy();
#endif

    return EXIT_SUCCESS;
}


