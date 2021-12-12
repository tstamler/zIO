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

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define __USE_GNU
#include <assert.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <skiplist.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <tas_sockets.h>
#include <unistd.h>
#include <utils.h>

//#define OPT_THRESHOLD 0xfffffffffffffffff
#define OPT_THRESHOLD 65535
#define OPT_THRESHOLD_1M 1024000

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK ~(PAGE_SIZE - 1)  // 0xfffffffff000

#define MAX_UFFD_MSGS 10

#define UFFD_PROTO

#define LOGON 0
#if LOGON
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...) \
  while (0) {    \
  }
#endif

#define LOG_STATS(...) fprintf(stderr, __VA_ARGS__)

long uffd = -1;

pthread_t fault_thread, stats_thread;

static inline void ensure_init(void);

struct addr_encoding {
  uint64_t addr;
  uint32_t len;
  uint64_t code;
  uint8_t bytes[64];
};

struct addr_track {
  uint64_t last_addr;
  uint64_t original;
  uint16_t size;
};

struct addr_track roll_addr[2048];

uint64_t num_fast_writes, num_slow_writes, num_fast_copy, num_slow_copy,
    num_faults;

/* Function pointers to the libc functions */
static int (*libc_socket)(int domain, int type, int protocol) = NULL;
static int (*libc_close)(int sockfd) = NULL;
static int (*libc_shutdown)(int sockfd, int how) = NULL;
static int (*libc_bind)(int sockfd, const struct sockaddr *addr,
                        socklen_t addrlen) = NULL;
static int (*libc_connect)(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen) = NULL;
static int (*libc_listen)(int sockfd, int backlog) = NULL;
static int (*libc_accept4)(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen, int flags) = NULL;
static int (*libc_accept)(int sockfd, struct sockaddr *addr,
                          socklen_t *addrlen) = NULL;
static int (*libc_fcntl)(int sockfd, int cmd, ...) = NULL;
static int (*libc_getsockopt)(int sockfd, int level, int optname, void *optval,
                              socklen_t *optlen) = NULL;
static int (*libc_setsockopt)(int sockfd, int level, int optname,
                              const void *optval, socklen_t optlen) = NULL;
static int (*libc_getsockname)(int sockfd, struct sockaddr *addr,
                               socklen_t *addrlen) = NULL;
static int (*libc_getpeername)(int sockfd, struct sockaddr *addr,
                               socklen_t *addrlen) = NULL;
static ssize_t (*libc_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len,
                            int flags) = NULL;
static ssize_t (*libc_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr,
                                socklen_t *addrlen) = NULL;
static ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg,
                               int flags) = NULL;
static ssize_t (*libc_readv)(int sockfd, const struct iovec *iov,
                             int iovcnt) = NULL;
static ssize_t (*libc_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset) = NULL;
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len,
                            int flags) = NULL;
static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len,
                              int flags, const struct sockaddr *dest_addr,
                              socklen_t addrlen) = NULL;
static ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg,
                               int flags) = NULL;
static ssize_t (*libc_writev)(int sockfd, const struct iovec *iov,
                              int iovcnt) = NULL;
static int (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
                          fd_set *exceptfds, struct timeval *timeout) = NULL;
static int (*libc_pselect)(int nfds, fd_set *readfds, fd_set *writefds,
                           fd_set *exceptfds, const struct timespec *timeout,
                           const sigset_t *sigmask) = NULL;

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static void (*libc_free)(void *ptr);
static void *(*libc_realloc)(void *ptr, size_t new_size);

skiplist addr_list;

void print_trace(void) {
  char **strings;
  size_t i, size;
  enum Constexpr { MAX_SIZE = 1024 };
  void *array[MAX_SIZE];
  size = backtrace(array, MAX_SIZE);
  strings = backtrace_symbols(array, size);
  for (i = 0; i < size; i++) LOG("%s\n", strings[i]);
  free(strings);
}

#if USED
int socket(int domain, int type, int protocol) {
  ensure_init();

  // LINUX COPY PROTOTYPE, NEVER USE TAS
  return libc_socket(domain, type, protocol);

  /* if not a TCP socket, pass call to libc */
  /*if (domain != AF_INET || type != SOCK_STREAM) {
    return libc_socket(domain, type, protocol);
  }

  return tas_socket(domain, type, protocol);*/
}

int close(int sockfd) {
  int ret;
  ensure_init();
  if ((ret = tas_close(sockfd)) == -1 && errno == EBADF) {
    return libc_close(sockfd);
  }
  return ret;
}

int shutdown(int sockfd, int how) {
  int ret;
  ensure_init();
  if ((ret = tas_shutdown(sockfd, how)) == -1 && errno == EBADF) {
    return libc_shutdown(sockfd, how);
  }
  return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int ret;
  ensure_init();
  if ((ret = tas_bind(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_bind(sockfd, addr, addrlen);
  }
  return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int ret;
  ensure_init();
  if ((ret = tas_connect(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_connect(sockfd, addr, addrlen);
  }
  return ret;
}

int listen(int sockfd, int backlog) {
  int ret;
  ensure_init();
  if ((ret = tas_listen(sockfd, backlog)) == -1 && errno == EBADF) {
    return libc_listen(sockfd, backlog);
  }
  return ret;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  int ret;
  ensure_init();
  if ((ret = tas_accept4(sockfd, addr, addrlen, flags)) == -1 &&
      errno == EBADF) {
    return libc_accept4(sockfd, addr, addrlen, flags);
  }
  return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret;
  ensure_init();
  if ((ret = tas_accept(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_accept(sockfd, addr, addrlen);
  }
  return ret;
}

int fcntl(int sockfd, int cmd, ...) {
  int ret, arg;
  va_list val;
  ensure_init();

  va_start(val, cmd);
  arg = va_arg(val, int);
  va_end(val);

  if ((ret = tas_fcntl(sockfd, cmd, arg)) == -1 && errno == EBADF) {
    return libc_fcntl(sockfd, cmd, arg);
  }
  return ret;
}

int getsockopt(int sockfd, int level, int optname, void *optval,
               socklen_t *optlen) {
  int ret;
  ensure_init();
  if ((ret = tas_getsockopt(sockfd, level, optname, optval, optlen)) == -1 &&
      errno == EBADF) {
    return libc_getsockopt(sockfd, level, optname, optval, optlen);
  }
  return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
               socklen_t optlen) {
  int ret;
  ensure_init();
  if ((ret = tas_setsockopt(sockfd, level, optname, optval, optlen)) == -1 &&
      errno == EBADF) {
    return libc_setsockopt(sockfd, level, optname, optval, optlen);
  }
  return ret;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret;
  ensure_init();
  if ((ret = tas_getsockname(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_getsockname(sockfd, addr, addrlen);
  }
  return ret;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret;
  ensure_init();
  if ((ret = tas_getpeername(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_getpeername(sockfd, addr, addrlen);
  }
  return ret;
}
#endif

#if USED
ssize_t read(int sockfd, void *buf, size_t count) {
  ssize_t ret = 0;
  static void *prev_addr, *prev_orig;  //, *max_addr;
  static size_t prev_len;
  uint64_t original;
  ensure_init();

  const int can_call_recv = (count > OPT_THRESHOLD);

  if (can_call_recv) {
    ret = libc_recv(sockfd, buf, count, MSG_WAITALL);
  } else {
    ret = libc_read(sockfd, buf, count);
  }

  const int read_error = (ret == -1);
  if (read_error) {
    perror("linux read");
    return ret;
  }

  // do {
  // ret = libc_read(sockfd, buf, count);
  // if (ret == -1 && errno != EAGAIN) {
  // perror("linux read");
  // return ret;
  // }
  // } while (errno == EAGAIN);

  LOG("tas read %zu bytes, page mask %lx, socket %d\n", ret,
      ((uint64_t)buf) & PAGE_MASK, sockfd);

  const int can_optimize = (ret > OPT_THRESHOLD);
  if (can_optimize) {
    LOG("reading from network at %p, size %zu, key %lx, original %p\n", buf,
        ret, ((uint64_t)buf) & PAGE_MASK, (uint64_t)buf);

    skiplist_insert(&addr_list, ((uint64_t)buf) & PAGE_MASK, (uint64_t)buf,
                    count, 0);
  }

  return ret;

#if 0
    // TODO: What is roll_addr?
    // LOG("returned addr %p, highest so far %p\n", original, max_addr);
    LOG("old roll_addr %p, prev_addr %p, prev_len %zu\n",
        roll_addr[sockfd].last_addr, prev_addr, prev_len);
    if ((((uint64_t)prev_addr + prev_len) & PAGE_MASK) ==
            (((uint64_t)buf) & PAGE_MASK) &&
        prev_len) {
      // roll_addr[sockfd].last_addr = (uint64_t) prev_addr + prev_len;
      roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
      roll_addr[sockfd].size = prev_len + ret;
      roll_addr[sockfd].original = prev_orig;
      LOG("small addr found\n");
    } else {
      if (roll_addr[sockfd].last_addr == (uint64_t)buf) {
        roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
        roll_addr[sockfd].size += ret;
        LOG("rolling, old original %p new original %p\n",
            roll_addr[sockfd].original, buf);
      } else {
        roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
        roll_addr[sockfd].size = ret;
        roll_addr[sockfd].original = (uint64_t)buf;
        LOG("not rolling, size is %zu, should be %zu\n", roll_addr[sockfd].size,
            ret);
      }
      LOG("small addr not found: prev %p, current %p\n",
          (uint64_t)prev_addr + prev_len, (uint64_t)buf);
    }

    uint64_t old_addr =
        (roll_addr[sockfd].last_addr - roll_addr[sockfd].size) & PAGE_MASK;
    LOG("new roll_addr %p, size %zu, original %p inserting at %p\n",
        roll_addr[sockfd].last_addr, roll_addr[sockfd].size, buf, old_addr);
    skiplist_insert(&addr_list, old_addr, roll_addr[sockfd].original,
                    roll_addr[sockfd].size, 0);
  }

  if (((uint64_t)buf - ret) == prev_addr) {
    prev_len += ret;
  } else {
    prev_addr = buf;
    prev_len = ret;
    prev_orig = buf;
  }

  return ret;
#endif
}
#endif

#if USED
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_recv(sockfd, buf, len, flags)) == -1 && errno == EBADF) {
    ret = libc_recv(sockfd, buf, len, flags);
  }
  return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_recvfrom(sockfd, buf, len, flags, src_addr, addrlen)) == -1 &&
      errno == EBADF) {
    return libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  }
  return ret;
}
#endif

/*
Application can call recvmsg in a row when a large message comes.

For exmaple, If the MongoDB client sends a message of 1M, there are multiple
recvmsg with size 64K and continuous buffers. When continuos buffers come in a
row, this function will update the entry of the skiplist that has the very first
address, rather than newly inserting an entry.
*/

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  ensure_init();

  ssize_t ret = libc_recvmsg(sockfd, msg, flags);

#if 0
  int i;
  for (i = 0; i < msg->msg_iovlen; i++) {
    uint64_t target_addr = (uint64_t)msg->msg_iov[i].iov_base;
    uint64_t target_len = msg->msg_iov[i].iov_len;
    uint64_t target_aligned_addr = target_addr & PAGE_MASK;

    if (target_len > OPT_THRESHOLD)
      skiplist_insert(&addr_list, target_aligned_addr, target_addr, target_len, 0);
  }

  return ret;
#else
  const int cannot_optimize = (ret <= OPT_THRESHOLD);

  static uint64_t starting_addr = 0, predict_next_addr = 0;

  if (cannot_optimize) {
    starting_addr = 0;
    predict_next_addr = 0;

    return ret;
  }

  int i;
  for (i = 0; i < msg->msg_iovlen; i++) {
    uint64_t target_addr = (uint64_t)msg->msg_iov[i].iov_base;
    uint64_t target_len = msg->msg_iov[i].iov_len;
    uint64_t target_aligned_addr = target_addr & PAGE_MASK;

    const int is_consecutive = (predict_next_addr == target_aligned_addr);

    if (is_consecutive) {
      snode *entry = skiplist_search(&addr_list, starting_addr);

      if (entry) {
        entry->len += target_len;

        skiplist_insert(&addr_list, target_aligned_addr, starting_addr,
                        target_len, target_addr - starting_addr);
      } else {
        fprintf(stderr, "Invalid codepath\n");
        abort();
      }
    } else {
      skiplist_insert(&addr_list, target_aligned_addr, target_addr, target_len,
                      0);

      starting_addr = target_aligned_addr;
    }

    predict_next_addr = (target_addr + target_len) & PAGE_MASK;
  }

  return ret;
#endif
}

#if USED
ssize_t readv(int sockfd, const struct iovec *iov, int iovcnt) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_readv(sockfd, iov, iovcnt)) == -1 && errno == EBADF) {
    return libc_readv(sockfd, iov, iovcnt);
  }
  return ret;
}
#endif

#if USED
ssize_t write(int sockfd, const void *buf, size_t count) {
  ssize_t ret, ret2;
  ensure_init();
  // if ((ret = tas_write(sockfd, buf, count)) == -1 && errno == EBADF) {
  size_t new_len = count;
  ret = 0;
  if (count > OPT_THRESHOLD) {
    snode *entry = skiplist_search(&addr_list, ((uint64_t)buf) & PAGE_MASK);
    LOG("writing to linux from %p, bounded %p, size %zu, entry %p\n", buf,
        ((uint64_t)buf) & PAGE_MASK, count, entry);
    if (entry) LOG("entry->len: %lu\n", entry->len);
    if (entry) {
      new_len = count - entry->len;

      // clean up old skiplist entry

      uint64_t src_bounded = ((uint64_t)buf) & PAGE_MASK;
      uint32_t register_len = (count & PAGE_MASK) - PAGE_SIZE;
#if 0	    
	    uint64_t mmap_ret = mmap((void*) (src_bounded + PAGE_SIZE), (count & PAGE_MASK) - PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	    if(mmap_ret != (src_bounded + PAGE_SIZE)){
	    //if(munmap((void*) (dest_bounded + PAGE_SIZE), register_len) < 0){
	    //if(mprotect((void*) (dest_bounded + PAGE_SIZE), register_len, PROT_NONE) < 0){
	    	LOG("write bad mmap return %p... parameters %p, %zu\n", mmap_ret, src_bounded + PAGE_SIZE, (count & PAGE_MASK) - PAGE_SIZE);
		perror("memcpy mmap");
		abort();
	    }
#else
      struct uffdio_range uffdio_unregister;
      uffdio_unregister.start = src_bounded + PAGE_SIZE;
      uffdio_unregister.len = register_len;

      LOG("uffd unregistering addr %p-%p, len %zu\n", src_bounded + PAGE_SIZE,
          src_bounded + PAGE_SIZE + register_len, register_len);
      if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) {
        perror("ioctl uffdio_unregister");
        abort();
      }
#endif
      LOG("preparing encoding of size %zu, new_len = %zu, count = %zu, "
          "entry->len=%zu\n",
          sizeof(struct addr_encoding), new_len, count, entry->len);
      struct addr_encoding *code = ((void *)buf) + new_len;
      code->addr = entry->orig;
      code->len = entry->len;
      code->code = 0xdeadbeef;
      new_len = sizeof(struct addr_encoding);
      // new_len += sizeof(struct addr_encoding);
      ret = count;
      LOG("encoding ready\n");
      num_fast_writes++;
    } else {
      LOG("entry %p not found\n", buf);

      num_slow_writes++;
      return libc_write(sockfd, buf, count);
      // printf("entry not found\n");
    }
    skiplist_delete(&addr_list, ((uint64_t)buf) & PAGE_MASK);
    LOG("write from %p len %zu out of %zu\n", entry->orig, entry->len, count);

    ret = libc_write(sockfd, entry->orig, count);

    LOG("actually wrote %zu\n", ret);

    return ret;
    // return libc_write(sockfd, entry->orig, count);
  }
  skiplist_delete(&addr_list, ((uint64_t)buf) & PAGE_MASK);
  LOG("write from %p len %zu out of %zu\n", entry->orig, entry->len, count);

  ret = libc_write(sockfd, entry->orig, count);

  LOG("actually wrote %zu\n", ret);

  return ret;
  // return libc_write(sockfd, entry->orig, count);
}
// LOG("write len %zu\n", new_len);
// new_len = sizeof(struct addr_encoding);
// ret = count;

if (new_len > OPT_THRESHOLD) num_slow_writes++;

ret2 = libc_write(sockfd, buf, new_len);

if (ret2 < 0 || ret == 0)
  return ret2;
else
  return ret;
// return libc_write(sockfd, buf, new_len);
//}
// return ret;
}
#endif

ssize_t pwrite(int sockfd, const void *buf, size_t count, off_t offset) {
  ensure_init();

  ssize_t ret = 0;
  size_t new_len = count;

  const int cannot_optimize = (count <= OPT_THRESHOLD_1M);

  if (cannot_optimize) {
    return libc_pwrite(sockfd, buf, new_len, offset);
  }

  snode *entry = skiplist_search(&addr_list, ((uint64_t)buf) & PAGE_MASK);
  LOG("writing to linux from %p, bounded %p, size %zu, entry %p\n", buf,
      ((uint64_t)buf) & PAGE_MASK, count, entry);

  if (!entry) {
    LOG("entry %p not found\n", buf);

    num_slow_writes++;
    return libc_pwrite(sockfd, buf, count, offset);
  }

  new_len = count - entry->len;

  // clean up old skiplist entry

  uint64_t src_bounded = ((uint64_t)buf) & PAGE_MASK;
  uint32_t register_len = (count & PAGE_MASK) - PAGE_SIZE;

  struct uffdio_range uffdio_unregister;
  uffdio_unregister.start = src_bounded + PAGE_SIZE;
  uffdio_unregister.len = register_len;

  LOG("uffd unregistering addr %p-%p, len %zu\n", src_bounded + PAGE_SIZE,
      src_bounded + PAGE_SIZE + register_len, register_len);

  const int unregister_failed =
      (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1);

  if (unregister_failed) {
    perror("ioctl uffdio_unregister");
    abort();
  }

  num_fast_writes++;

  skiplist_delete(&addr_list, ((uint64_t)buf) & PAGE_MASK);
  LOG("write from %p len %zu out of %zu\n", entry->orig, entry->len, count);

  ret = libc_pwrite(sockfd, (const void *)entry->orig, count, offset);

  LOG("actually wrote %zu\n", ret);

  return ret;
}

#if USED
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_send(sockfd, buf, len, flags)) == -1 && errno == EBADF) {
    return libc_send(sockfd, buf, len, flags);
  }
  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_sendto(sockfd, buf, len, flags, dest_addr, addrlen)) == -1 &&
      errno == EBADF) {
    return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  }
  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_sendmsg(sockfd, msg, flags)) == -1 && errno == EBADF) {
    return libc_sendmsg(sockfd, msg, flags);
  }
  return ret;
}

ssize_t writev(int sockfd, const struct iovec *iov, int iovcnt) {
  ssize_t ret;
  ensure_init();
  if ((ret = tas_writev(sockfd, iov, iovcnt)) == -1 && errno == EBADF) {
    return libc_writev(sockfd, iov, iovcnt);
  }
  return ret;
}

// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
// struct timeval *timeout) {
// return libc_select(nfds, readfds, writefds, exceptfds, timeout);
// // return tas_select(nfds, readfds, writefds, exceptfds, timeout);
// }
//
// int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
// const struct timespec *timeout, const sigset_t *sigmask) {
// return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
// // return tas_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
// }

// int epoll_create(int size) { return tas_epoll_create(size); }
//
// int epoll_create1(int flags) { return tas_epoll_create1(flags); }
//
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
// return tas_epoll_ctl(epfd, op, fd, event);
// }
//
// int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
// int timeout) {
// return tas_epoll_wait(epfd, events, maxevents, timeout);
// }
//
// int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
// int timeout, const sigset_t *sigmask) {
// return tas_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
// }
#endif

void *memcpy(void *dest, const void *src, size_t n) {
  ensure_init();

  static uint64_t prev_start, prev_end;
  // TODO: parse big copy for multiple small copies

  if (n > OPT_THRESHOLD_1M) {
    LOG("copying %p-%p to %p-%p, size %zu\n", src, src + n, dest, dest + n, n);
    // skiplist_dump(&addr_list);
    snode *entry = skiplist_search(&addr_list, ((uint64_t)src) & PAGE_MASK);
    if (entry) {
      uint64_t original = entry->orig;
      uint32_t length = entry->len;
      uint64_t old_offset = entry->offset;

      uint64_t dest_bounded = ((uint64_t)dest) & PAGE_MASK;
      uint64_t src_bounded = ((uint64_t)src) & PAGE_MASK;
      uint64_t offset = ((uint64_t)dest) - dest_bounded;
      uint64_t register_len = (n - PAGE_SIZE) & PAGE_MASK;

      if ((uint64_t)dest > prev_start && (uint64_t)dest < prev_end) goto done;
      // clean up old skiplist entry
      uint64_t ret;
#ifdef UFFD_PROTO

      // the offset ends up corresponding to the amount of data at the END of
      // the buffer thus, this might *seem* backward

      LOG("mmaping for uffd at %p, length %zu\n", dest_bounded + PAGE_SIZE,
          register_len);
      ret = (uint64_t)mmap(((void *)(dest_bounded + PAGE_SIZE)), register_len,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
      if (ret != (dest_bounded + PAGE_SIZE)) {
        // if(munmap((void*) (dest_bounded + PAGE_SIZE), register_len) < 0){
        // if(mprotect((void*) (dest_bounded + PAGE_SIZE), register_len,
        // PROT_NONE) < 0){
        fprintf(stderr, "bad mmap return %p... parameters %p, %zu\n", ret,
                dest_bounded + PAGE_SIZE, register_len);
        perror("memcpy mmap");
        abort();
      }

      struct uffdio_register uffdio_register;
      uffdio_register.range.start = dest_bounded + PAGE_SIZE;
      uffdio_register.range.len = register_len;
      uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
      uffdio_register.ioctls = 0;

      LOG("uffd registering addr %p-%p, len %zu\n", dest_bounded + PAGE_SIZE,
          dest_bounded + PAGE_SIZE + register_len, register_len);
      if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        perror("ioctl uffdio_register");
        abort();
      }
      LOG("successfully mapped and registered %p\n", dest_bounded + PAGE_SIZE);
      // memcpy((dest_bounded+PAGE_SIZE), src, 32);

      LOG("inserting original %p at location %p\n", original, dest_bounded);
      // skiplist_insert(&addr_list, dest_bounded, original, length, offset);
      skiplist_insert(&addr_list, dest_bounded, original, n, offset);
      // fprintf(stderr, "inserting %lx ret %d\n", ((uint64_t) dest) &
      // PAGE_MASK, ret); skiplist_dump(&addr_list);

      // print_trace();
    done:
      prev_start = (uint64_t)dest;
      prev_end = (uint64_t)dest + n;
      num_fast_copy++;

      return dest;
#else
      //#endif
      skiplist_insert(&addr_list, dest_bounded, original, length, offset);
      // fprintf(stderr, "inserting %lx ret %d\n", ((uint64_t) dest) &
      // PAGE_MASK, ret); skiplist_dump(&addr_list);
#endif

#ifdef NO_COPY_TEST
      return libc_memcpy(dest, src, 32);
#endif
    } else {
      LOG("appropriate size copy, but can't find %p in skiplist\n",
          ((uint64_t)src) & PAGE_MASK);
      num_slow_copy++;
    }
  } else if (n > 1024)
    LOG("sizeable, but not large enough copy from %p to %p of size %zu\n", dest,
        src, n);
  return libc_memcpy(dest, src, n);
}

void free(void *ptr) {
  uint64_t ptr_bounded = (uint64_t)ptr & PAGE_MASK;
  snode *entry = skiplist_search(&addr_list, ptr_bounded);

  if (entry) {
    if (entry->orig == ptr) {
      // mark for later free
      entry->free = 1;
      return;
    } else {
      skiplist_delete(&addr_list, ptr_bounded);
    }
  }
  return libc_free(ptr);
}

void *realloc(void *ptr, size_t new_size) {
  ensure_init();

  // it should just be malloc, and then unmapping then registering the malloced
  // pointer with userfaultfd

  int cannot_optimize = (new_size <= OPT_THRESHOLD_1M || ptr == NULL);

  if (cannot_optimize) {
    return libc_realloc(ptr, new_size);
  }

  snode *entry = skiplist_search(&addr_list, ((uint64_t)ptr) & PAGE_MASK);
  cannot_optimize = (entry == NULL);

  if (cannot_optimize) {
    return libc_realloc(ptr, new_size);
  }

  LOG("realloc from %p and size: %zu\n", ptr, new_size);

  void *new_ptr;
  int ret = posix_memalign(&new_ptr, PAGE_SIZE, new_size);
  if (ret == -1) {
    perror("failed to posix_memalign");
    new_ptr = malloc(new_size);
    if (!new_ptr) {
      perror("failed to malloc");
      abort();
    }
  }

  uint64_t original = entry->orig;

  uint64_t new_ptr_bounded = ((uint64_t)new_ptr) & PAGE_MASK;
  uint64_t ptr_bounded = ((uint64_t)ptr) & PAGE_MASK;
  uint64_t offset = ((uint64_t)new_ptr) - new_ptr_bounded;

  uint64_t register_len = (new_size - PAGE_SIZE) & PAGE_MASK;

  // ret = munmap(new_ptr_bounded + PAGE_SIZE, register_len);
  // if (ret == -1) {
  //   perror("failed to unmap");
  //   abort();
  // }

  LOG("mmaping for uffd at %p, length %zu\n", new_ptr_bounded + PAGE_SIZE,
      register_len);
  uint64_t mapped_addr = (uint64_t)mmap(
      ((void *)(new_ptr_bounded + PAGE_SIZE)), register_len,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if (mapped_addr != (new_ptr_bounded + PAGE_SIZE)) {
    fprintf(stderr, "bad mmap return %p... parameters %p, %zu\n", ret,
            new_ptr_bounded + PAGE_SIZE, register_len);
    perror("memcpy mmap");
    abort();
  }

  struct uffdio_register uffdio_register;
  uffdio_register.range.start = new_ptr_bounded + PAGE_SIZE;
  uffdio_register.range.len = register_len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  uffdio_register.ioctls = 0;

  LOG("uffd registering addr %p-%p, len %zu\n", new_ptr_bounded + PAGE_SIZE,
      new_ptr_bounded + PAGE_SIZE + register_len, register_len);
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    perror("ioctl uffdio_register");
    abort();
  }

  LOG("successfully mapped and registered %p\n", new_ptr_bounded + PAGE_SIZE);
  LOG("inserting original %p at location %p\n", original, new_ptr_bounded);

  skiplist_insert(&addr_list, new_ptr_bounded, original, new_size, offset);

  print_trace();

  return new_ptr;
}

#if USED
void *memmove(void *dest, const void *src, size_t n) {
  ensure_init();
  if (n > OPT_THRESHOLD) {
    LOG("moving %p to %p, size %zu\n", src, dest, n);
    // return dest;
  } else if (n > 1024)
    LOG("sizeable, but not large enough move from %p to %p of size %zu\n", dest,
        src, n);
  return libc_memmove(dest, src, n);
}
#endif

/******************************************************************************/
/* Helper functions */

static void *bind_symbol(const char *sym) {
  void *ptr;
  if ((ptr = dlsym(RTLD_NEXT, sym)) == NULL) {
    fprintf(stderr, "flextcp socket interpose: dlsym failed (%s)\n", sym);
    abort();
  }
  return ptr;
}

void handle_missing_fault(uint64_t page_boundary, uint32_t fault_flags) {
  snode *entry;
  int i = 0;
  uint64_t base_addr;

  LOG("handling fault at %p\n", page_boundary);

  void *ret =
      mmap((void *)page_boundary, PAGE_SIZE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);

  if (ret == MAP_FAILED) {
    perror("failed to handle missing fault");
    abort();
  }

  num_faults++;
  return;

  for (i = 1; i < 50; i++) {
    base_addr = page_boundary - i * PAGE_SIZE;
    LOG("searching for %p\n", base_addr);
    entry = skiplist_search(&addr_list, base_addr);
    if (entry) break;
  }

  if (entry == NULL) {
    LOG("page fault can't find skiplist entry, aborting\n");
    abort();
  }
  LOG("found %p entry at %p, lookup %p, size %lu, offset %p\n", entry,
      base_addr, entry->lookup, entry->len, entry->offset);

  uint64_t original = entry->orig;
  uint32_t length = entry->len;
  uint64_t offset = entry->offset;
  void *newptr;

  LOG("mapping page fault at %p with %zu bytes\n", base_addr + PAGE_SIZE,
      (length & PAGE_MASK) - PAGE_SIZE);
  newptr = mmap((void *)(base_addr + PAGE_SIZE),
                (length & PAGE_MASK) - PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  // newptr = mmap((void*)(base_addr + PAGE_SIZE), length - PAGE_SIZE,
  // PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS, 0, 0);
  if (newptr < 0) {
    perror("newptr mmap");
    assert(0);
  }

  if (((uint64_t)newptr) != (base_addr + PAGE_SIZE)) {
    fprintf(stderr, "page fault mmap: newptr != base_addr... %p != %p\n",
            newptr, base_addr + PAGE_SIZE);
  }
  LOG("copying into page fault at %p from %p with %zu\n", base_addr + PAGE_SIZE,
      ((void *)original) + (PAGE_SIZE - offset),
      (length & PAGE_MASK) - PAGE_SIZE);

  LOG("testing base from %p to %p\n", base_addr + PAGE_SIZE,
      base_addr + length);
  /*for(i = PAGE_SIZE; i < length; i+=PAGE_SIZE) {
          LOG("copying %zu\n", i);
          libc_memcpy((void*) base_addr+i, test_buf+i, PAGE_SIZE);
  }
          //libc_memcpy((void*) (base_addr + PAGE_SIZE), test_buf, (length &
  PAGE_MASK) - PAGE_SIZE); LOG("testing original\n"); for(i = PAGE_SIZE -
  offset; i < length; i+=PAGE_SIZE) { LOG("copying %zu\n", i);
  libc_memcpy(test_buf+i, (void*) original+i, PAGE_SIZE);
  }
  libc_memcpy(test_buf, (void*) (original + (PAGE_SIZE - offset)), (length &
  PAGE_MASK) - PAGE_SIZE);

  libc_memcpy((void*) (base_addr + PAGE_SIZE), (void*) (original + (PAGE_SIZE
  - offset)), (length & PAGE_MASK) - PAGE_SIZE); assert(page_boundary);*/

  skiplist_delete(&addr_list, base_addr);
  num_faults++;
}

void *print_stats() {
  while (1) {
    LOG_STATS(
        "fast copies: %lu\tslow copies: %lu\tfast writes: %lu\tslow "
        "writes: %lu\tpage faults: %lu\n",
        num_fast_copy, num_slow_copy, num_fast_writes, num_slow_writes,
        num_faults);
    num_fast_writes = num_slow_writes = num_fast_copy = num_slow_copy =
        num_faults = 0;
    sleep(1);
  }
}

void *handle_fault() {
  static struct uffd_msg msg[MAX_UFFD_MSGS];
  ssize_t nread;
  uint64_t fault_addr;
  uint64_t fault_flags;
  uint64_t page_boundry;
  struct uffdio_range range;
  int ret;
  int nmsgs;
  int i;

  // cpu_set_t cpuset;
  // pthread_t thread;
  // thread = pthread_self();

  // CPU_ZERO(&cpuset);

  // CPU_SET(FAULT_THREAD_CPU, &cpuset);

  // int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

  // if (s != 0) {
  //  perror("pthread_setaffinity_np");
  //  assert(0);
  //}

  for (;;) {
    struct pollfd pollfd;
    int pollres;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    pollres = poll(&pollfd, 1, -1);

    LOG("waking for page fault?\n");

    switch (pollres) {
      case -1:
        perror("poll");
        assert(0);
      case 0:
        fprintf(stderr, "poll read 0\n");
        continue;
      case 1:
        break;
      default:
        fprintf(stderr, "unexpected poll result\n");
        assert(0);
    }

    if (pollfd.revents & POLLERR) {
      fprintf(stderr, "pollerr\n");
      assert(0);
    }

    if (!pollfd.revents & POLLIN) {
      continue;
    }

    nread = libc_read(uffd, &msg[0], MAX_UFFD_MSGS * sizeof(struct uffd_msg));
    if (nread == 0) {
      fprintf(stderr, "EOF on userfaultfd\n");
      assert(0);
    }
    if (nread < 0) {
      if (errno == EAGAIN) {
        continue;
      }
      perror("read");
      assert(0);
    }

    if ((nread % sizeof(struct uffd_msg)) != 0) {
      fprintf(stderr, "invalid msg size: [%ld]\n", nread);
      assert(0);
    }

    nmsgs = nread / sizeof(struct uffd_msg);
    for (i = 0; i < nmsgs; i++) {
      if (msg[i].event & UFFD_EVENT_PAGEFAULT) {
        LOG("page fault event\n");
        fault_addr = (uint64_t)msg[i].arg.pagefault.address;
        fault_flags = msg[i].arg.pagefault.flags;

        page_boundry = fault_addr & ~(PAGE_SIZE - 1);

        LOG("handling fault at %p, calling function %p\n", fault_addr,
            &handle_missing_fault);
        handle_missing_fault(page_boundry, fault_flags);

        range.start = (uint64_t)page_boundry;
        range.len = PAGE_SIZE;

        ret = ioctl(uffd, UFFDIO_WAKE, &range);

        if (ret < 0) {
          perror("uffdio wake");
          assert(0);
        }
      } else if (msg[i].event & UFFD_EVENT_UNMAP) {
        fprintf(stderr, "Received an unmap event\n");
        assert(0);
      } else if (msg[i].event & UFFD_EVENT_REMOVE) {
        fprintf(stderr, "received a remove event\n");
        assert(0);
      } else {
        fprintf(stderr, "received a non page fault event\n");
        assert(0);
      }
    }
  }
}

static void init(void) {
  libc_socket = bind_symbol("socket");
  libc_close = bind_symbol("close");
  libc_shutdown = bind_symbol("shutdown");
  libc_bind = bind_symbol("bind");
  libc_connect = bind_symbol("connect");
  libc_listen = bind_symbol("listen");
  libc_accept4 = bind_symbol("accept4");
  libc_accept = bind_symbol("accept");
  libc_fcntl = bind_symbol("fcntl");
  libc_getsockopt = bind_symbol("getsockopt");
  libc_setsockopt = bind_symbol("setsockopt");
  libc_getsockname = bind_symbol("getsockname");
  libc_getpeername = bind_symbol("getpeername");
  libc_read = bind_symbol("read");
  libc_recv = bind_symbol("recv");
  libc_recvfrom = bind_symbol("recvfrom");
  libc_recvmsg = bind_symbol("recvmsg");
  libc_readv = bind_symbol("readv");
  libc_write = bind_symbol("write");
  libc_pwrite = bind_symbol("pwrite");
  libc_send = bind_symbol("send");
  libc_sendto = bind_symbol("sendto");
  libc_sendmsg = bind_symbol("sendmsg");
  libc_writev = bind_symbol("writev");
  libc_select = bind_symbol("select");
  libc_pselect = bind_symbol("pselect");

  libc_memmove = bind_symbol("memmove");
  libc_memcpy = bind_symbol("memcpy");
  libc_free = bind_symbol("free");
  libc_realloc = bind_symbol("realloc");

  // new tracking code
  skiplist_init(&addr_list);

#ifdef UFFD_PROTO
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
    perror("uffd");
    abort();
  }

  num_fast_writes = num_slow_writes = num_fast_copy = num_slow_copy =
      num_faults = 0;

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features =
      0;  // UFFD_FEATURE_PAGEFAULT_FLAG_WP |  UFFD_FEATURE_MISSING_SHMEM |
          // UFFD_FEATURE_MISSING_HUGETLBFS;// | UFFD_FEATURE_EVENT_UNMAP |
          // UFFD_FEATURE_EVENT_REMOVE;
  uffdio_api.ioctls = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
    perror("ioctl uffdio_api");
    abort();
  }

  if (pthread_create(&fault_thread, NULL, handle_fault, 0) != 0) {
    perror("fault thread create");
    abort();
  }

  printf("launching stats\n");
  if (pthread_create(&stats_thread, NULL, print_stats, 0) != 0) {
    perror("stats thread create");
    abort();
  }

  LOG("uffd initialized\n");
#endif

  // if (tas_init() != 0) {
  //  abort();
  //}
}

static inline void ensure_init(void) {
  static volatile uint32_t init_cnt = 0;
  static volatile uint8_t init_done = 0;
  static __thread uint8_t in_init = 0;

  if (init_done == 0) {
    /* during init the socket functions will be used to connect to the kernel
     * on a unix socket, so make sure that runs through. */
    if (in_init) {
      return;
    }

    if (__sync_fetch_and_add(&init_cnt, 1) == 0) {
      in_init = 1;
      init();
      in_init = 0;
      MEM_BARRIER();
      init_done = 1;
    } else {
      while (init_done == 0) {
        pthread_yield();
      }
      MEM_BARRIER();
    }
  }
}
