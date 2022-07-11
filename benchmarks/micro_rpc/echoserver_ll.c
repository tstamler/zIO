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

#include <tas_ll.h>
#include <utils.h>
#include <utils_rng.h>

#include "../common/microbench.h"

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
    struct flextcp_connection conn;
    void *buf_1;
    void *buf_2;
    int len_1;
    int len_2;
    int closed;

    struct connection *next;
    char buf[];
};

struct core {
    struct flextcp_context ctx;
    struct flextcp_listener listener;
    int cn;
    uint32_t opaque;
    struct utils_rng rng;
    uint8_t *workingset;
    struct connection *conns;
    uint32_t num_conns;
} __attribute__((aligned((64))));

enum rx_result {
  RX_SUCCESS = 0,
  RX_FAIL,
  RX_RETRY,
  RX_EOS,
};

/** Opening listener and wait for success */
static int open_listening(struct flextcp_context *ctx,
        struct flextcp_listener *l)
{
    struct flextcp_event ev;
    int ret;

    if (flextcp_listen_open(ctx, l, listen_port, listen_backlog,
          FLEXTCP_LISTEN_REUSEPORT) != 0)
    {
        fprintf(stderr, "flextcp_listen_open failed\n");
        return -1;
    }

    /* wait until listen request is done */
    while (1) {
        if ((ret = flextcp_context_poll(ctx, 1, &ev)) < 0) {
            fprintf(stderr, "init_listen: flextcp_context_poll failed\n");
            return -1;
        }

        /* skip if no event */
        if (ret == 0)  {
            continue;
        }

        if (ev.event_type != FLEXTCP_EV_LISTEN_OPEN) {
            fprintf(stderr, "init_listen: unexpected event type (%u)\n",
                    ev.event_type);
            continue;
        }

        if (ev.ev.listen_open.status != 0) {
            fprintf(stderr, "init_listen: listen open request failed\n");
            return -1;
        }

        break;
    }

    return 0;
}




static void prepare_core(struct core *c)
{
    int i, cn = c->cn;
    struct connection *co;

    if (working_set > 0) {
        if ((c->workingset = malloc(working_set)) == NULL) {
            fprintf(stderr, "[%d] working set alloc failed\n", cn);
            abort();
        }
    } else {
        c->workingset = NULL;
    }

    /* prepare listening socket */
    if (open_listening(&c->ctx, &c->listener) != 0) {
        fprintf(stderr, "[%d] working set alloc failed\n", cn);
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

        co->len_1 = co->len_2 = co->closed = 0;
        if (flextcp_listen_accept(&c->ctx, &c->listener, &co->conn) != 0) {
            fprintf(stderr, "[%d] listen_accept failed\n", cn);
            abort();
        }
    }
}

#if 0
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
#endif

static inline void thread_event_rx(struct core *co, struct flextcp_event *ev)
{
  struct connection *c = (struct connection *) ev->ev.conn_received.conn;
  size_t len;
  void *buf, *buf_2;
  ssize_t ret;

  if (c->len_1 == 0) {
    assert(c->len_2 == 0);
    c->buf_1 = ev->ev.conn_received.buf;
    c->len_1 = ev->ev.conn_received.len;
  } else if (c->buf_1 + c->len_1 == ev->ev.conn_received.buf) {
    assert(c->len_2 == 0);
    c->len_1 += ev->ev.conn_received.len;
  } else if (c->len_2 == 0) {
    c->buf_2 = ev->ev.conn_received.buf;
    c->len_2 = ev->ev.conn_received.len;
  } else if (c->buf_2 + c->len_2 == ev->ev.conn_received.buf) {
    c->len_2 += ev->ev.conn_received.len;
  } else {
    fprintf(stderr, "weird situation l1=%u l2=%u b1=%p b2=%p\n", c->len_1, c->len_2, c->buf_1, c->buf_2);
    abort();
  }

  while (c->len_1 + c->len_2 >= max_bytes) {
    ret = flextcp_connection_tx_alloc2(&c->conn, max_bytes, &buf, &len, &buf_2);
    if (ret != max_bytes) {
      fprintf(stderr, "thread_event_rx: tx alloc failed (%zd)\n", ret);
      abort();
    }

    /* TODO */
    assert(len == max_bytes);

    if (c->len_1 >= max_bytes) {
      memcpy(buf, c->buf_1, max_bytes);
      c->buf_1 += max_bytes;
      c->len_1 -= max_bytes;
      if (c->len_1 == 0) {
        c->buf_1 = c->buf_2;
        c->len_1 = c->len_2;
        c->len_2 = 0;
      }
    } else {
      memcpy(buf, c->buf_1, c->len_1);
      memcpy(buf + c->len_1, c->buf_2, max_bytes - c->len_1);

      c->buf_2 += max_bytes - c->len_1;
      c->len_2 -= max_bytes - c->len_1;
      c->buf_1 = c->buf_2;
      c->len_1 = c->len_2;
      c->len_2 = 0;
    }

    if (flextcp_connection_tx_send(&co->ctx, &c->conn, max_bytes) != 0) {
      fprintf(stderr, "thread_event_rx: tx_send failed\n");
      abort();
    }

    if (flextcp_connection_rx_done(&co->ctx, &c->conn, max_bytes) != 0) {
      fprintf(stderr, "thread_event_rx: rx_done failed\n");
      abort();
    }
  }

  assert(c->len_1 == 0);
}

static inline void thread_event_pf(struct core *co, struct flextcp_event *ev)
{
  if (ev->event_type == FLEXTCP_EV_CONN_RECEIVED)
    util_prefetch0(&((struct connection *) ev->ev.conn_received.conn)->len_1);

}

static inline void thread_event(struct core *co, struct flextcp_event *ev)
{
  struct connection *c;

  switch (ev->event_type) {
    case FLEXTCP_EV_LISTEN_NEWCONN:
      /*printf("thread_event: new conn\n");*/
      break;

    case FLEXTCP_EV_LISTEN_ACCEPT:
      if (ev->ev.listen_accept.status != 0) {
        fprintf(stderr, "thread_event: accept failed\n");
        abort();
      }
      /*printf("thread_event: accepted %p\n", ev->ev.listen_accept.conn);*/
      break;

    case FLEXTCP_EV_CONN_RECEIVED:
      thread_event_rx(co, ev);
      break;

    case FLEXTCP_EV_CONN_RXCLOSED:
      c = (struct connection *) ev->ev.conn_rxclosed.conn;
      /*printf("thread_event: rx closed %p\n", c);
      fflush(stdout);*/
      if (c->len_1 != 0)
        fprintf(stderr, "len1=%u\n", c->len_1);
      assert(c->len_1 == 0);
      if (flextcp_connection_tx_close(&co->ctx, &c->conn) != 0) {
        fprintf(stderr, "thread_event: tx close failed\n");
        abort();
      }
      break;

    case FLEXTCP_EV_CONN_TXCLOSED:
      c = (struct connection *) ev->ev.conn_txclosed.conn;
      /*printf("thread_event: tx closed %p\n", c);
      fflush(stdout);*/
      if (flextcp_connection_close(&co->ctx, &c->conn) != 0) {
        fprintf(stderr, "thread_event: connection close failed\n");
        abort();
      }
      break;

    case FLEXTCP_EV_CONN_CLOSED:
      c = (struct connection *) ev->ev.conn_closed.conn;
      /*printf("thread_event: closed %p\n", c);*/
      if (ev->ev.conn_closed.status != 0) {
        fprintf(stderr, "thread_event: connection close failed\n");
        abort();
      }

      c->len_1 = c->len_2 = c->closed = 0;
      if (flextcp_listen_accept(&co->ctx, &co->listener, &c->conn) != 0) {
        fprintf(stderr, "thread_event: connection accept failed\n");
        abort();
      }
      break;

    default:
      fprintf(stderr, "thread_event: unexpected event type %x\n",
          ev->event_type);
      abort();
  }
}

static void *thread_run(void *arg)
{
    struct core *co = arg;
    int n, i, cn;
    struct flextcp_event *evs;

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
        if ((n = flextcp_context_poll(&co->ctx, max_events, evs)) < 0) {
            abort();
        }
        for (i = 0; i < n; i++) {
            thread_event_pf(co, evs + i);
        }

        for (i = 0; i < n; i++) {
            thread_event(co, evs + i);
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

    if (argc < 4 || argc > 11) {
        fprintf(stderr, "Usage: ./echoserver PORT THREADS CONFIG [MAX-FLOWS] "
            "[MAX-BYTES] [OP-DELAY] [WORKING-SET] [ICACHE-SET] "
            "[LISTEN-BACKLOG] [MAX-EPEVENTS]\n");
        return EXIT_FAILURE;
    }
    listen_port = atoi(argv[1]);
    num_threads = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);

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

    if (flextcp_init() != 0) {
        fprintf(stderr, "flextcp_init failed\n");
        return EXIT_FAILURE;
    }

    pts = calloc(num_threads, sizeof(*pts));
    cs = calloc(num_threads, sizeof(*cs));
    if (pts == NULL || cs == NULL) {
        fprintf(stderr, "allocating thread handles failed\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < num_threads; i++) {
        cs[i].cn = i;
        if (flextcp_context_create(&cs[i].ctx) != 0) {
            fprintf(stderr, "flextcp_context_create failed\n");
            return EXIT_FAILURE;
        }
    }

    for (i = 0; i < num_threads; i++) {
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
      pause();
    }
}


