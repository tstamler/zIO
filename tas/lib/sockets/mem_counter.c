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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <time.h>
#include <unistd.h>
#include <utils.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void ensure_init(void);

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static void *(*libc_realloc)(void *ptr, size_t new_size);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset);
static ssize_t (*libc_writev)(int sockfd, const struct iovec *iov, int iovcnt);
static ssize_t (*libc_pwritev)(int sockfd, const struct iovec *iov, int iovcnt,
                               off_t offset);
static size_t (*libc_fwrite)(const void *buffer, size_t size, size_t count,
                             FILE *stream);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);

static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*libc_recvfrom)(int sockfd, void *restrict buf, size_t len,
                                int flags, struct sockaddr *restrict src_addr,
                                socklen_t *restrict addrlen);
static ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg, int flags);

static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len,
                              int flags, const struct sockaddr *dest_addr,
                              socklen_t addrlen);
static ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);

int eq_(const char *s1, const char *s2, size_t n) {
  if (!s1 || !s2)
    return 0;

  int i = 0;
  for (i = 0; i < n; i++) {
    if (s1[i] != s2[i])
      return 0;
  }
  return 1;
}

int contain_(const char *s1, const char *s2, size_t s1_len, size_t s2_len) {
  if (!s1 || !s2)
    return 0;

  int i;
  for (i = 0; i < s1_len; i++) {
    if (s1[i] == s2[0]) {
      if (eq_(&s1[i], s2, s2_len)) {
        return i;
      }
    }
  }

  return 0;
}

#define ALWAYS_CHECK 0
#define KEYWORD "nono"
#define KEYWORD_LEN 4
  //#define OPT_THRESHOLD 65535 // 0xfffffffffffffffff
  //#define OPT_THRESHOLD 57343
  #define OPT_THRESHOLD 1000000
  
#define OPT_THRESHOLD_1M 65535

#define PAGE_MASK 0xfffffffff000

#define print(addr1, addr2, len)                                               \
  do {                                                                         \
    const int is_only_addr1 = (addr1 && !addr2);                               \
    const int is_only_addr2 = (!addr1 && addr2);                               \
    if (is_only_addr1) {                                                       \
      fprintf(stdout, "%s len:%zu %p(%p)\n", __func__, len, addr1,            \
              (uint64_t)addr1 &PAGE_MASK);                                     \
    } else if (is_only_addr2) {                                                \
      fprintf(stdout, "%s len:%zu %p(%p)\n", __func__, len, addr2,            \
              (uint64_t)addr2 &PAGE_MASK);                                     \
    } else {                                                                   \
      fprintf(stdout, "%s len:%zu %p(%p)->%p(%p)\n", __func__, len, addr1,   \
              (uint64_t)addr1 &PAGE_MASK, addr2, (uint64_t)addr2 &PAGE_MASK);  \
    }                                                                          \
  } while (0)

void print_trace(void) {
  char **strings;
  size_t i, size;
  enum Constexpr { MAX_SIZE = 1024 };
  void *array[MAX_SIZE];
  size = backtrace(array, MAX_SIZE);
  strings = backtrace_symbols(array, size);
  for (i = 0; i < 15; i++)
    printf("%s\n", strings[i]);
  free(strings);
}


void *memcpy(void *dest, const void *src, size_t n) {
  ensure_init();

  const char can_print =
      contain_(src, KEYWORD, n, KEYWORD_LEN) || n > OPT_THRESHOLD_1M;

  if (can_print) {
    print(src, dest, n);
  }

  return libc_memcpy(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {
  ensure_init();

  const char can_print =
      contain_(src, KEYWORD, n, KEYWORD_LEN) || n > OPT_THRESHOLD_1M;

  if (can_print) {
    print(src, dest, n);
  }

  return libc_memmove(dest, src, n);
}

void *realloc(void *ptr, size_t new_size) {
  ensure_init();

  void *new_ptr = libc_realloc(ptr, new_size);

  const char can_print = contain_(new_ptr, KEYWORD, new_size, KEYWORD_LEN) ||
                         new_size > OPT_THRESHOLD_1M;

  if (can_print) {
    print(ptr, new_ptr, new_size);
  }

  return new_ptr;
}

ssize_t write(int sockfd, const void *buf, size_t count) {
  ensure_init();

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD_1M;

  if (can_print) {
    print(buf, 0, count);
  }

  return libc_write(sockfd, buf, count);
}
ssize_t pwrite(int sockfd, const void *buf, size_t count, off_t offset) {
  ensure_init();

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD_1M;

  if (can_print) {
    print(buf, 0, count);
  }

  return libc_pwrite(sockfd, buf, count, offset);
}

ssize_t writev(int sockfd, const struct iovec *iov, int iovcnt) {
  ensure_init();

  ssize_t ret = libc_writev(sockfd, iov, iovcnt);

  int i;
  for (i = 0; i < iovcnt; i++) {
    const char can_print =
        contain_(iov->iov_base, KEYWORD, iov->iov_len, KEYWORD_LEN) ||
        iov->iov_len > OPT_THRESHOLD;
    if (can_print) {
      print(iov->iov_base, 0, iov->iov_len);
    }
  }

  return ret;
}
ssize_t pwritev(int sockfd, const struct iovec *iov, int iovcnt, off_t offset) {
  ensure_init(); /*
                   if (iovcnt >= OPT_THRESHOLD && strncmp ((char
                   *)iov[0].iov_base, "My data", 7) == 0)
                   {
                   } */
  ssize_t ret = libc_pwritev(sockfd, iov, iovcnt, offset);

  int i;
  for (i = 0; i < iovcnt; i++) {
    const char can_print =
        contain_(iov->iov_base, KEYWORD, iov->iov_len, KEYWORD_LEN) ||
        iov->iov_len > OPT_THRESHOLD;
    if (can_print) {
      print(iov->iov_base, 0, iov->iov_len);
    }
  }

  return ret;
}

size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream) {
  ensure_init();

  const char can_print =
      contain_(buffer, KEYWORD, size, KEYWORD_LEN) || size > OPT_THRESHOLD;

  if (can_print) {
    print(buffer, 0, size);
  }

  return libc_fwrite(buffer, size, count, stream);
}

ssize_t read(int fd, void *buf, size_t count) {
  ensure_init();

  ssize_t ret = libc_read(fd, buf, count);

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD;

  if (can_print) {
    print(buf, 0, count);
  }

  return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  ensure_init();

  ssize_t ret = libc_pread(fd, buf, count, offset);

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD;

  if (can_print) {
    print(buf, 0, count);
  }

  return ret;
}

ssize_t recv(int sockfd, void *buf, size_t count, int flags) {
  ensure_init();

  ssize_t ret = libc_recv(sockfd, buf, count, flags);

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD;

  if (can_print) {
    print(buf, 0, count);
  }

  return ret;
}

ssize_t recvfrom(int sockfd, void *restrict buf, size_t len, int flags,
                 struct sockaddr *restrict src_addr,
                 socklen_t *restrict addrlen) {
  ensure_init();

  ssize_t ret = libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

  fprintf(stdout, "%s %ld\n", __func__, ret);

  return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  ensure_init();

  ssize_t ret = libc_recvmsg(sockfd, msg, flags);

  int i;
  for (i = 0; i < msg->msg_iovlen; i++) {
    const char can_print = msg->msg_iov[i].iov_len > OPT_THRESHOLD;
    if (can_print) {
      print(msg->msg_iov[i].iov_base, 0, msg->msg_iov[i].iov_len);
    }
  }

  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t count, int flags) {
  ensure_init();

  const char can_print =
      contain_(buf, KEYWORD, count, KEYWORD_LEN) || count > OPT_THRESHOLD;

  if (can_print) {
    print(buf, 0, count);
  }

  return libc_send(sockfd, buf, count, flags);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  ensure_init();

  fprintf(stdout, "%s %lu %s\n", __func__, len, (const char *)buf);

  return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ensure_init();

  int i;
  for (i = 0; i < msg->msg_iovlen; i++) {
    const char can_print = contain_(msg->msg_iov[i].iov_base, KEYWORD,
                                    msg->msg_iov[i].iov_len, KEYWORD_LEN) ||
                           msg->msg_iov[i].iov_len > OPT_THRESHOLD;
    if (can_print) {
      print(msg->msg_iov[i].iov_base, 0, msg->msg_iov[i].iov_len);
    }
  }

  return libc_sendmsg(sockfd, msg, flags);
}

static void *bind_symbol(const char *sym) {
  void *ptr;
  if ((ptr = dlsym(RTLD_NEXT, sym)) == NULL) {
    // fprintf (stderr, "flextcp socket interpose: dlsym failed (%s)\n", sym);
    abort();
  }
  return ptr;
}

static void init(void) {
  libc_memmove = bind_symbol("memmove");
  libc_memcpy = bind_symbol("memcpy");
  libc_realloc = bind_symbol("realloc");
  libc_write = bind_symbol("write");
  libc_writev = bind_symbol("writev");
  libc_pwrite = bind_symbol("pwrite");
  libc_pwritev = bind_symbol("pwritev");
  libc_fwrite = bind_symbol("fwrite");
  libc_read = bind_symbol("read");
  libc_pread = bind_symbol("pread");
  libc_recv = bind_symbol("recv");
  libc_recvfrom = bind_symbol("recvfrom");
  libc_recvmsg = bind_symbol("recvmsg");
  libc_send = bind_symbol("send");
  libc_sendto = bind_symbol("sendto");
  libc_sendmsg = bind_symbol("sendmsg");
}

static inline void ensure_init(void) {
  static volatile uint32_t init_cnt = 0;
  static volatile uint8_t init_done = 0;
  static __thread uint8_t in_init = 0;

  if (init_done == 0) {
    /* during init the socket functions will be used to connect to the kernel on
     * a unix socket, so make sure that runs through. */
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

#ifdef __cplusplus
}
#endif
