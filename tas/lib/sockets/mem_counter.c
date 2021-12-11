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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <skiplist.h>
#include <utils.h>

#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void ensure_init(void);

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset);
static ssize_t (*libc_writev)(int sockfd, const struct iovec *iov, int iovcnt);
static ssize_t (*libc_pwritev)(int sockfd, const struct iovec *iov, int iovcnt,
                               off_t offset);
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

int memcpy_cnt;
int memmove_cnt;
int recv_cnt;
int write_cnt;

size_t total_size_copied;
size_t total_size_moved;

struct timespec begin;

pthread_mutex_t mutex;

void print(void *dest, const void *src, size_t n) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  /* fprintf (stdout, "At %ld\n", (ts.tv_sec - begin.tv_sec) * 1000000000 + */
  /* 	   (ts.tv_nsec - begin.tv_nsec)); */
  fprintf(stdout, "dest: %p, src: %p, size: %lu\n", dest, src, n);
  fprintf(stdout, "src content: %s\n", (const char *)src);
  fprintf(stdout, "memcpy: %d, memmove: %d\n", memcpy_cnt, memmove_cnt);
  fprintf(stdout, "total_size_copied: %ld, total_size_moved: %ld\n",
          total_size_copied, total_size_moved);
  fflush(stdout);
}

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
#define OPT_THRESHOLD 0xfffffffffffffffff

#define BASIC_CONDITION (eq_(src, "My_data", 7ul))

#define RADOS_CONDITION (

#define GRPC_KV_CONDITION (eq_(src, "key", 3ul) || eq_(src, "value", 5ul))

#define TENSOR_CONDITION (/*eq_ (src, "mnist", 5ul)*/ n == 3548)

#define FILTER_CONDITION (BASIC_CONDITION)

void *memcpy(void *dest, const void *src, size_t n) {

  pthread_mutex_lock(&mutex);

  ensure_init();

  int off = 0;
  if ((off = contain_(src, "My_data", n, 7)) || n > OPT_THRESHOLD) {
    ++memcpy_cnt;
    total_size_copied += n;
    print(dest, src, n);

    goto out;
  }

  /* if ((off = contain_ (src, "$$", n, 2))) */
  /*   { */
  /* 	++memcpy_cnt; */
  /* 	total_size_copied += n; */
  /* 	print (dest, src + off, n); */

  /* 	goto out; */
  /*   } */

  /* if (n >= 4096) */
  /*   { */
  /* 	++memcpy_cnt; */
  /* 	total_size_copied += n; */
  /* 	print (dest, src, n); */

  /* 	goto out; */
  /*   } */

out:
  pthread_mutex_unlock(&mutex);
  return libc_memcpy(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {

  pthread_mutex_lock(&mutex);
  ensure_init();

  int off = 0;
  if ((off = contain_(src, "My_data", n, 7)) || n > OPT_THRESHOLD) {
    ++memmove_cnt;
    total_size_moved += n;
    print(dest, src, n);
  }

  pthread_mutex_unlock(&mutex);
  return libc_memmove(dest, src, n);
}

ssize_t write(int sockfd, const void *buf, size_t count) {
  ensure_init();

  /* if (contain_ ((const char *)buf, "head", count, 4)) { */
  /*   fprintf (stdout, "write %d %lu %s\n", */
  /* 	       sockfd, count, (char *)buf); */
  /* } */

  ssize_t ret = libc_write(sockfd, buf, count);

  int off = 0;
  //    if ((off = contain_(buf, "My_data", count, 7))) {
  fprintf(stdout, "write data %ld %s\n", ret, (const char *)buf);
  //    }

  return ret;
}
ssize_t pwrite(int sockfd, const void *buf, size_t count, off_t offset) {

  pthread_mutex_lock(&mutex);

  ensure_init();
  /*   if (count >= OPT_THRESHOLD && strncmp ((char *)buf, "My data", 7) == 0)
       {
       } */

  ssize_t ret = libc_pwrite(sockfd, buf, count, offset);

  int off = 0;
  if ((off = contain_(buf, "My_data", count, 7))) {
    fprintf(stdout, "%s %lu %*.s\n", __func__, ret, 10, (char *)buf + off);
    goto out;
  }

  if ((off = contain_(buf, "7777777", count, 7))) {
    fprintf(stdout, "%s %lu %*.s\n", __func__, ret, 10, (char *)buf + off);
    goto out;
  }

out:
  pthread_mutex_unlock(&mutex);
  return ret;
}

ssize_t writev(int sockfd, const struct iovec *iov, int iovcnt) {
  ensure_init();

  ssize_t ret = libc_writev(sockfd, iov, iovcnt);

  int i;
  for (i = 0; i < iovcnt; i++) {
    int off = 0;
    if ((off = contain_((const char *)iov->iov_base, "zz", iov->iov_len, 2))) {
      fprintf(stdout, "writev %d: %lu %s\n", i, iov->iov_len,
              (const char *)iov->iov_base + off);
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

  fprintf(stdout, "pwritev %ld\n", ret);

  return ret;
}

ssize_t read(int fd, void *buf, size_t count) {

  pthread_mutex_lock(&mutex);

  ensure_init();

  ssize_t ret = libc_read(fd, buf, count);

  if (contain_(buf, "My_data", count, 7)) {
    fprintf(stdout, "%s %lu %s\n", __func__, ret, (const char *)buf);
  }
  /* fprintf(stdout, "read %d %lu %.*s\n", */
  /* 	    fd, count, (int)ret, (char *)buf); */

  pthread_mutex_unlock(&mutex);
  return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {

  pthread_mutex_lock(&mutex);

  ensure_init();

  ssize_t ret = libc_pread(fd, buf, count, offset);

  //    if (contain_(buf, "My_data", count, 7)) {
  fprintf(stdout, "%s %lu %s\n", __func__, ret, (const char *)buf);
  //    }
  /* fprintf(stdout, "read %d %lu %.*s\n", */
  /* 	    fd, count, (int)ret, (char *)buf); */

  pthread_mutex_unlock(&mutex);
  return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  ensure_init();

  ssize_t ret = libc_recv(sockfd, buf, len, flags);

  ++recv_cnt;

  if (contain_(buf, "My_data", len, 7)) {
    fprintf(stdout, "recv %d %lu %s\n", sockfd, len, (char *)buf);
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

  fprintf(stdout, "%s %ld\n", __func__, ret);

  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  ensure_init();

  ssize_t ret = libc_send(sockfd, buf, len, flags);
  //  if (contain_(buf, "My_data", len, 7)) {
  fprintf(stdout, "%s %lu %*.s\n", __func__, len, (int)len, (const char *)buf);
  //}
  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  ensure_init();

  fprintf(stdout, "%s %lu %s\n", __func__, len, (const char *)buf);

  return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ensure_init();

  ssize_t ret = libc_sendmsg(sockfd, msg, flags);

  fprintf(stdout, "%s %ld\n", __func__, ret);

  return ret;
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
  libc_write = bind_symbol("write");
  libc_writev = bind_symbol("writev");
  libc_pwrite = bind_symbol("pwrite");
  libc_pwritev = bind_symbol("pwritev");
  libc_read = bind_symbol("read");
  libc_pread = bind_symbol("pread");
  libc_recv = bind_symbol("recv");
  libc_recvfrom = bind_symbol("recvfrom");
  libc_recvmsg = bind_symbol("recvmsg");
  libc_send = bind_symbol("send");
  libc_sendto = bind_symbol("sendto");
  libc_sendmsg = bind_symbol("sendmsg");

  memcpy_cnt = 0;
  memmove_cnt = 0;
  write_cnt = 0;
  recv_cnt = 0;

  total_size_copied = 0;
  total_size_moved = 0;

  clock_gettime(CLOCK_MONOTONIC, &begin);
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
