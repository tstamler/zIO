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

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef USE_MTCP
# include <mtcp_api.h>
# include <mtcp_epoll.h>
#else
# include <sys/epoll.h>
#endif


#ifdef USE_MTCP
    typedef mctx_t ssctx_t;
    typedef struct mtcp_epoll_event ss_epev_t;

    #define SS_EPOLL_CTL_ADD MTCP_EPOLL_CTL_ADD
    #define SS_EPOLL_CTL_DEL MTCP_EPOLL_CTL_DEL
    #define SS_EPOLL_CTL_MOD MTCP_EPOLL_CTL_MOD

    #define SS_EPOLLIN  MTCP_EPOLLIN
    #define SS_EPOLLOUT MTCP_EPOLLOUT
    #define SS_EPOLLERR MTCP_EPOLLERR
    #define SS_EPOLLHUP MTCP_EPOLLHUP
#else
    struct ssctx_st { };
    typedef struct ssctx_st *ssctx_t;
    typedef struct epoll_event ss_epev_t;

    #define SS_EPOLL_CTL_ADD EPOLL_CTL_ADD
    #define SS_EPOLL_CTL_DEL EPOLL_CTL_DEL
    #define SS_EPOLL_CTL_MOD EPOLL_CTL_MOD

    #define SS_EPOLLIN  EPOLLIN
    #define SS_EPOLLOUT EPOLLOUT
    #define SS_EPOLLERR EPOLLERR
    #define SS_EPOLLHUP EPOLLHUP
#endif

static inline int ss_socket(ssctx_t sctx, int f, int s, int p)
{
#ifdef USE_MTCP
    return mtcp_socket(sctx, f, s, p);
#else
    return socket(f, s, p);
#endif
}

static inline int ss_close(ssctx_t sctx, int fd)
{
#ifdef USE_MTCP
    return mtcp_close(sctx, fd);
#else
    return close(fd);
#endif
}


static inline int ss_set_nonblock(ssctx_t sctx, int fd)
{
#ifdef USE_MTCP
    return mtcp_setsock_nonblock(sctx, fd);
#else
    int flag;

    if ((flag = fcntl(fd, F_GETFL, 0)) == -1) {
        return -1;
    }
    flag |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flag);
#endif
}

static inline int ss_set_reuseport(ssctx_t sctx, int fd)
{
#ifdef USE_MTCP
    return 0;
#else
    int flag;
    flag = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
#endif
}

static inline int ss_set_nonagle(ssctx_t sctx, int fd)
{
#ifdef USE_MTCP
    return 0;
#else
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif
}

static inline int ss_connect(ssctx_t sctx, int fd, const struct sockaddr *addr,
      socklen_t addrlen)
{
#ifdef USE_MTCP
    return mtcp_connect(sctx, fd, addr, addrlen);
#else
    return connect(fd, addr, addrlen);
#endif
}

static inline int ss_bind(ssctx_t sctx, int fd, const struct sockaddr *addr,
        socklen_t addrlen)
{
#ifdef USE_MTCP
    return mtcp_bind(sctx, fd, addr, addrlen);
#else
    return bind(fd, addr, addrlen);
#endif
}

static inline int ss_listen(ssctx_t sctx, int fd, int backlog)
{
#ifdef USE_MTCP
    return mtcp_listen(sctx, fd, backlog);
#else
    return listen(fd, backlog);
#endif
}

static inline int ss_accept(ssctx_t sctx, int fd, struct sockaddr *addr,
        socklen_t *addrlen)
{
#ifdef USE_MTCP
    return mtcp_accept(sctx, fd, addr, addrlen);
#else
    return accept(fd, addr, addrlen);
#endif

}

static inline int ss_getsockopt(ssctx_t sctx, int fd, int level, int optname,
        void *optval, socklen_t *optlen)
{
#ifdef USE_MTCP
    return mtcp_getsockopt(sctx, fd, level, optname, optval, optlen);
#else
    return getsockopt(fd, level, optname, optval, optlen);
#endif
}

static inline ssize_t ss_read(ssctx_t sctx, int fd, void *buf, size_t cnt)
{
#ifdef USE_MTCP
    return mtcp_read(sctx, fd, buf, cnt);
#else
    return read(fd, buf, cnt);
#endif
}

static inline ssize_t ss_write(ssctx_t sctx, int fd, const void *buf,
      size_t cnt)
{
#ifdef USE_MTCP
    return mtcp_write(sctx, fd, (void *) buf, cnt);
#else
    return write(fd, buf, cnt);
#endif
}


static inline int ss_epoll_create(ssctx_t sctx, int size)
{
#ifdef USE_MTCP
    return mtcp_epoll_create(sctx, size);
#else
    return epoll_create(size);
#endif
}

static inline int ss_epoll_wait(ssctx_t sctx, int epfd, ss_epev_t *evs,
        int nevs, int timeout)
{
#ifdef USE_MTCP
    return mtcp_epoll_wait(sctx, epfd, evs, nevs, timeout);
#else
    return epoll_wait(epfd, evs, nevs, timeout);
#endif
}

static inline int ss_epoll_ctl(ssctx_t sctx, int epfd, int op, int fd,
        ss_epev_t *ev)
{
#ifdef USE_MTCP
    return mtcp_epoll_ctl(sctx, epfd, op, fd, ev);
#else
    return epoll_ctl(epfd, op, fd, ev);
#endif
}
