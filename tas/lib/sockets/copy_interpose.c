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
#include <asm-generic/errno-base.h>
#include <bits/types/struct_iovec.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
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
#include <signal.h>
#include <skiplist.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <tas_sockets.h>
#include <unistd.h>
#include <utils.h>

//#define OPT_THRESHOLD 0xfffffffffffffffff
#define OPT_THRESHOLD 983040
//#define OPT_THRESHOLD 978944
//#define OPT_THRESHOLD 57343

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK ~(PAGE_SIZE - 1) // 0xfffffffff000

#define MAX_UFFD_MSGS 1

#define UFFD_PROTO

#define ENABLED_LOCK 1

#define LOGON 0
#if LOGON
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...)                                                               \
  while (0) {                                                                  \
  }
#endif

#define LOG_STATS(...) fprintf(stderr, __VA_ARGS__)

#define print(addr1, addr2, len)                                               \
  do {                                                                         \
    const int is_only_addr1 = (addr1 && !addr2);                               \
    const int is_only_addr2 = (!addr1 && addr2);                               \
    if (is_only_addr1) {                                                       \
      fprintf(stdout, "%s len:%zu %p(%lu)\n", __func__, len, addr1,            \
              (uint64_t)addr1 &PAGE_MASK);                                     \
    } else if (is_only_addr2) {                                                \
      fprintf(stdout, "%s len:%zu %p(%lu)\n", __func__, len, addr2,            \
              (uint64_t)addr2 &PAGE_MASK);                                     \
    } else {                                                                   \
      fprintf(stdout, "%s len:%zu %p(%lu)->%p(%lu)\n", __func__, len, addr1,   \
              (uint64_t)addr1 &PAGE_MASK, addr2, (uint64_t)addr2 &PAGE_MASK);  \
    }                                                                          \
  } while (0)

#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define IS_ALIGNED(addr) ((uint64_t)addr % PAGE_MASK == 0)
#define PAGE_ALIGN_DOWN(addr) ((void *)((uint64_t)addr & PAGE_MASK))
#define PAGE_ALIGN_UP(addr)                                                    \
  ((void *)((uint64_t)PAGE_ALIGN_DOWN(addr) + PAGE_SIZE))
#define LEFT_FRINGE_LEN(addr)                                                  \
  (((uint64_t)PAGE_ALIGN_UP(addr) - (uint64_t)addr) % PAGE_SIZE)
#define RIGHT_FRINGE_LEN(len, off) ((len - off) % PAGE_SIZE)

#define REGISTER_FAULT(reg_start, reg_len)                                     \
  do {                                                                         \
    struct uffdio_register uffdio_register;                                    \
    uffdio_register.range.start = (uint64_t)reg_start;                         \
    uffdio_register.range.len = (uint64_t)reg_len;                             \
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;                       \
    uffdio_register.ioctls = 0;                                                \
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {                \
      fprintf(stderr, "%d: ", __LINE__);                                       \
      perror("ioctl uffdio_register");                                         \
      fprintf(stderr, "range: %p %lu\n", reg_start, reg_len);                  \
      abort();                                                                 \
    }                                                                          \
  } while (0)

#define UNREGISTER_FAULT(reg_start, reg_len)                                   \
  do {                                                                         \
    struct uffdio_range uffdio_unregister;                                     \
    uffdio_unregister.start = (uint64_t)reg_start;                             \
    uffdio_unregister.len = (uint64_t)reg_len;                                 \
    if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) {            \
      fprintf(stderr, "%d: ", __LINE__);                                       \
      perror("ioctl uffdio_unregister");                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

#define IOV_MAX_CNT 10000

long uffd = -1;

pthread_t fault_thread, stats_thread;

#if ENABLED_LOCK
pthread_mutex_t mu;
#endif

static inline void ensure_init(void);

uint64_t num_fast_writes, num_slow_writes, num_fast_copy, num_slow_copy,
    num_faults;

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset) = NULL;
static ssize_t (*libc_pwritev)(int sockfd, const struct iovec *iov, int iovcnt,
                               off_t offset) = NULL;
static void (*libc_free)(void *ptr);
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t count,
                            int flags);
static ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);

static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg, int flags);

skiplist addr_list;

void print_trace(void) {
  char **strings;
  size_t i, size;
  enum Constexpr { MAX_SIZE = 1024 };
  void *array[MAX_SIZE];
  size = backtrace(array, MAX_SIZE);
  strings = backtrace_symbols(array, size);
  for (i = 0; i < 15; i++)
    printf("%s\n", strings[i]);
  /* if (strings) */
  /*   libc_free(strings); */
}

ssize_t pwrite(int sockfd, const void *buf, size_t count, off_t offset) {
  ensure_init();

  const int cannot_optimize = (count <= OPT_THRESHOLD);

  if (cannot_optimize) {
    num_slow_writes++;
    return libc_pwrite(sockfd, buf, count, offset);
  }

  const uint64_t left_fringe_len = LEFT_FRINGE_LEN(buf);
  const uint64_t right_fringe_len = RIGHT_FRINGE_LEN(count, left_fringe_len);

  struct iovec iovec[IOV_MAX_CNT];
  int iovcnt = 0;

  uint64_t off = 0;
  uint64_t remaining_len = count;

#if ENABLED_LOCK
  pthread_mutex_lock(&mu);
#endif
  while (remaining_len > 0) {
    snode *entry =
        skiplist_search_buffer_fallin(&addr_list, (uint64_t)buf + off);

    if (entry) {
      iovec[iovcnt].iov_base = entry->orig + (buf - entry->addr) + off;
      iovec[iovcnt].iov_len = entry->len;

      // UNREGISTER_FAULT(entry->addr + entry->offset, entry->len);
      // skiplist_delete(&addr_list, entry->lookup);
    } else {
      iovec[iovcnt].iov_base = buf + off;
      iovec[iovcnt].iov_len = LEFT_FRINGE_LEN(iovec[iovcnt].iov_base) == 0
                                  ? PAGE_SIZE
                                  : LEFT_FRINGE_LEN(iovec[iovcnt].iov_base);
    }

    iovec[iovcnt].iov_len = MIN(remaining_len, iovec[iovcnt].iov_len);

    off += iovec[iovcnt].iov_len;
    remaining_len -= iovec[iovcnt].iov_len;

    ++iovcnt;

    if (iovcnt >= IOV_MAX_CNT) {
      errno = ENOMEM;
      perror("pwrite iov is full");
      abort();
    }
  }

  num_fast_writes++;

#if ENABLED_LOCK
  pthread_mutex_unlock(&mu);
#endif

#if LOGON
  {
    int i;
    int total_len = 0;
    for (i = 0; i < iovcnt; i++) {
      printf("iov[%d]: base %p len %lu\n", i, iovec[i].iov_base,
             iovec[i].iov_len);
      total_len += iovec[i].iov_len;
    }

    printf("total: %d, count: %d\n", total_len, count);
  }
#endif

  return libc_pwritev(sockfd, iovec, iovcnt, offset);
}

inline void *mmapcpy(void *dest, const void *src, size_t n) {
  void *ret =
      mmap(dest, n, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  libc_memcpy(dest, src, n);
}

inline void copy_from_original(void *orig_addr) {
  LOG("[%s] the original buffer %p exists\n", __func__, orig_addr);
  snode *entry = skiplist_front(&addr_list);
  while (entry) {
    snode *entry_to_be_deleted = 0;
    if (entry->orig != entry->addr &&
        PAGE_ALIGN_DOWN(orig_addr) == PAGE_ALIGN_DOWN(entry->orig)) {
      mmapcpy(entry->addr + entry->offset, entry->orig + entry->offset,
              entry->len);

      LOG("[%s] copy from %p-%p to %p-%p, len: %lu\n", __func__,
          entry->orig + entry->offset, entry->orig + entry->offset + entry->len,
          entry->addr + entry->offset, entry->addr + entry->offset + entry->len,
          entry->len);

      entry_to_be_deleted = entry;
    }
    if (entry_to_be_deleted)
      skiplist_delete(&addr_list, entry_to_be_deleted->lookup);
    entry = snode_get_next(&addr_list, entry);
  }
}

void *dest_in_processing = 0;

void *memcpy(void *dest, const void *src, size_t n) {
  ensure_init();

  static uint64_t prev_start, prev_end;
  // TODO: parse big copy for multiple small copies

  const char cannot_optimize = (n <= OPT_THRESHOLD);

  if (cannot_optimize) {
    dest_in_processing = 0;
    return libc_memcpy(dest, src, n);
  }

  LOG("[%s] copying %p-%p to %p-%p, size %zu\n", __func__, src, src + n, dest,
      dest + n, n);

  const uint64_t core_src_buffer_addr = src + LEFT_FRINGE_LEN(src);

  if (dest_in_processing == 0)
    dest_in_processing = dest;

#if ENABLED_LOCK
  pthread_mutex_lock(&mu);
#endif

  snode *src_entry = skiplist_search(&addr_list, core_src_buffer_addr);
  if (src_entry) {
#if LOGON
    LOG("[%s] found src entry\n", __func__);
    snode_dump(src_entry);
#endif
    if (src_entry->orig == src_entry->addr) {
      struct uffdio_register uffdio_register;
      uffdio_register.range.start =
          (uint64_t)(src_entry->addr + src_entry->offset);
      uffdio_register.range.len = (uint64_t)src_entry->len;
      uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
      uffdio_register.ioctls = 0;
      if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        if (errno == EINVAL) {
          LOG("[%s] write-protection fault fault by userfaultfd may not be"
              "supported by the current kernel\n");
        }
        perror("register with WP");
        abort();
      }
    }

    size_t left_fringe_len = LEFT_FRINGE_LEN(dest);
    size_t right_fringe_len = RIGHT_FRINGE_LEN(n, left_fringe_len);

    if (dest_in_processing == dest) {
      if (left_fringe_len == 0) {
        if (LEFT_FRINGE_LEN(src) > 0) {
          left_fringe_len = PAGE_SIZE;
        }
      }
    }

    uint64_t core_dst_buffer_addr = dest + left_fringe_len;

    snode dest_entry;
    dest_entry.lookup = core_dst_buffer_addr;
    dest_entry.orig =
        src_entry->orig + ((long long)src - (long long)src_entry->addr);
    dest_entry.addr = dest;
    dest_entry.len =
        MIN(src_entry->len, n - (left_fringe_len + right_fringe_len));
    dest_entry.offset = left_fringe_len;

    if (left_fringe_len > 0) {
      LOG("[%s] copy the left fringe %p-%p->%p-%p len: %zu\n", __func__, src,
          src + left_fringe_len, dest, dest + left_fringe_len, left_fringe_len);

      libc_memcpy(dest, src, left_fringe_len);
    }

    size_t remaining_len = n - left_fringe_len;

    if (dest_entry.len > OPT_THRESHOLD) {
      if (PAGE_ALIGN_DOWN(dest_entry.addr) !=
          PAGE_ALIGN_DOWN(dest_entry.orig)) {
        skiplist_insert_entry(&addr_list, &dest_entry);
        void *ret = mmap(dest_entry.addr + dest_entry.offset, dest_entry.len,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        REGISTER_FAULT(dest_entry.addr + dest_entry.offset, dest_entry.len);

        LOG("[%s] tracking buffer %p-%p len:%lu\n", __func__,
            dest_entry.addr + dest_entry.offset,
            dest_entry.addr + dest_entry.offset + dest_entry.len,
            dest_entry.len);
#if LOGON
        snode_dump(&dest_entry);
#endif

      } /*else {
        libc_memcpy(dest_entry.addr + dest_entry.offset,
            dest_entry.orig + dest_entry.offset,
            dest_entry.len);
        LOG("[%s] copy buffer %p-%p -> %p-%p len:%lu\n", __func__,
            dest_entry.orig + dest_entry.offset,
            dest_entry.orig + dest_entry.offset + dest_entry.len,
            dest_entry.addr + dest_entry.offset,
            dest_entry.addr + dest_entry.offset + dest_entry.len,
      dest_entry.len);
      }*/

      remaining_len -= dest_entry.len;
    }

    LOG("[%s] remaining_len %zu out of %zu\n", __func__, remaining_len, n);

    // can be partial copy
    ++num_fast_copy;

#if ENABLED_LOCK
    pthread_mutex_unlock(&mu);
#endif

    if (remaining_len > 0)
      memcpy(dest + (n - remaining_len), src + (n - remaining_len),
             remaining_len);
  } else {
    // can be partial copy
    ++num_slow_copy;

#if ENABLED_LOCK
    pthread_mutex_unlock(&mu);
#endif

    size_t copy_len =
        LEFT_FRINGE_LEN(dest) > 0 ? LEFT_FRINGE_LEN(dest) : PAGE_SIZE;
    // size_t copy_len = PAGE_SIZE;
    libc_memcpy(dest, src, copy_len);
    memcpy(dest + copy_len, src + copy_len, n - copy_len);
    /* libc_memcpy(dest, src, n); */
  }

  return dest;
}

void free(void *ptr) {
  ensure_init();

  /*
  snode *entry = skiplist_front(&addr_list);
  while (entry) {
    if (entry->addr == ptr) {
      UNREGISTER_FAULT(entry->addr + entry->offset, entry->len);
      skiplist_delete(&addr_list, entry->lookup);
      break;
    }

    entry = snode_get_next(&addr_list, entry);
  }
  */
  return libc_free(ptr);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ensure_init();

  struct iovec iovec[IOV_MAX_CNT];
  int iovcnt = 0;

  int i;
  for (i = 0; i < msg->msg_iovlen; ++i) {
    void *buf = msg->msg_iov[i].iov_base;
    uint64_t count = msg->msg_iov[i].iov_len;

    LOG("[%s] base: %p, count: %zu\n", __func__, buf, count);

    if (count > OPT_THRESHOLD) {
#if ENABLED_LOCK
      pthread_mutex_lock(&mu);
#endif

      uint64_t off = 0;
      uint64_t remaining_len = count;

      while (remaining_len > 0) {
        snode *entry =
            skiplist_search_buffer_fallin(&addr_list, (uint64_t)buf + off);

        if (entry) {
          iovec[iovcnt].iov_base = entry->orig + (buf - entry->addr) + off;
          iovec[iovcnt].iov_len = entry->len;
        } else {
          iovec[iovcnt].iov_base = buf + off;
          iovec[iovcnt].iov_len = LEFT_FRINGE_LEN(iovec[iovcnt].iov_base) == 0
                                      ? PAGE_SIZE
                                      : LEFT_FRINGE_LEN(iovec[iovcnt].iov_base);
        }

        iovec[iovcnt].iov_len = MIN(remaining_len, iovec[iovcnt].iov_len);

        off += iovec[iovcnt].iov_len;
        remaining_len -= iovec[iovcnt].iov_len;

        ++iovcnt;

        if (iovcnt >= IOV_MAX_CNT) {
          errno = ENOMEM;
          perror("iov is full");
          abort();
        }
      }

#if ENABLED_LOCK
      pthread_mutex_unlock(&mu);
#endif
#if LOGON
      {
        int i;
        int total_len = 0;
        for (i = 0; i < iovcnt; i++) {
          printf("iov[%d]: base %p len %lu\n", i, iovec[i].iov_base,
                 iovec[i].iov_len);
          total_len += iovec[i].iov_len;
        }

        printf("total: %d, count: %d\n", total_len, count);
      }
#endif
    } else {
      iovec[iovcnt].iov_base = buf;
      iovec[iovcnt].iov_len = count;
      ++iovcnt;
    }
  }

  struct msghdr mh;
  libc_memcpy(&mh, msg, sizeof(struct msghdr));
  mh.msg_iov = iovec;
  mh.msg_iovlen = iovcnt;

  return libc_sendmsg(sockfd, &mh, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  ensure_init();

  ssize_t ret = libc_recvmsg(sockfd, msg, flags);

  int i;
  for (i = 0; i < msg->msg_iovlen; i++) {
    uint64_t left_fringe_len = LEFT_FRINGE_LEN(msg->msg_iov[i].iov_base);
    uint64_t right_fringe_len =
        RIGHT_FRINGE_LEN(msg->msg_iov[i].iov_len, left_fringe_len);
    ssize_t core_buffer_len =
        msg->msg_iov[i].iov_len - (left_fringe_len + right_fringe_len);

    LOG("[%s] i: %d, iov_base: %p, iov_len: %zu\n", __func__, i,
        msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    if (core_buffer_len > OPT_THRESHOLD) {
      snode new_entry;
      new_entry.lookup = msg->msg_iov[i].iov_base + left_fringe_len;
      new_entry.orig = (uint64_t)msg->msg_iov[i].iov_base;
      new_entry.addr = (uint64_t)msg->msg_iov[i].iov_base;
      new_entry.len = core_buffer_len;
      new_entry.offset = left_fringe_len;

#if ENABLED_LOCK
      pthread_mutex_lock(&mu);
#endif

      skiplist_insert_entry(&addr_list, &new_entry);

#if ENABLED_LOCK
      pthread_mutex_unlock(&mu);
#endif
    }
  }

  return ret;
}

void *memset(void *dest, int val, size_t len) {
  unsigned char *ptr = dest + LEFT_FRINGE_LEN(dest);

  if (addr_list.header && len > OPT_THRESHOLD) {
    ssize_t remaining_len = len;

#if ENABLED_LOCK
    pthread_mutex_lock(&mu);
#endif
    while (remaining_len > OPT_THRESHOLD) {
      snode *entry = skiplist_search(&addr_list, ptr);
      if (entry) {
        if (entry->orig == entry->addr) {
          copy_from_original(entry->addr);
        } else {
          void *ret = mmap(
              entry->addr + entry->offset, entry->len, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        }
        skiplist_delete(&addr_list, entry->lookup);

        remaining_len -= entry->len;
        ptr += entry->len;
      } else {
        remaining_len -= PAGE_SIZE;
        ptr += PAGE_SIZE;
      }
    }
#if ENABLED_LOCK
    pthread_mutex_unlock(&mu);
#endif
  }

  ptr = dest;
  while (len-- > 0)
    *ptr++ = val;

  return dest;
}

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

void *print_stats() {
  while (1) {
    LOG_STATS("fast copies: %lu\tslow copies: %lu\tfast writes: %lu\tslow "
              "writes: %lu\tpage faults: %lu\n",
              num_fast_copy, num_slow_copy, num_fast_writes, num_slow_writes,
              num_faults);
    num_fast_writes = num_slow_writes = num_fast_copy = num_slow_copy =
        num_faults = 0;
    sleep(1);
  }
}

void handle_missing_fault(void *fault_addr) {
  snode *fault_buffer_entry =
      skiplist_search_buffer_fallin(&addr_list, (uint64_t)fault_addr);
  if (!fault_buffer_entry) {
    /*
    fprintf(stderr, "[%s] no entry to handle fault addr: %p\n", __func__,
            fault_addr);
    skiplist_dump(&addr_list);
    abort();
    */
    void *ret =
        mmap(fault_addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  } else {

    void *copy_dst = fault_addr;
    void *copy_src =
        fault_buffer_entry->orig +
        ((long long)fault_addr - (long long)fault_buffer_entry->addr);
    size_t copy_len = PAGE_SIZE;

    if (fault_buffer_entry->addr + fault_buffer_entry->offset == fault_addr) {
      fault_buffer_entry->offset += PAGE_SIZE;
      fault_buffer_entry->len -= PAGE_SIZE;

      struct snode first_buffer_entry;
      first_buffer_entry.lookup =
          fault_buffer_entry->addr + fault_buffer_entry->offset;
      first_buffer_entry.orig = fault_buffer_entry->orig;
      first_buffer_entry.addr = fault_buffer_entry->addr;
      first_buffer_entry.len = fault_buffer_entry->len;
      first_buffer_entry.offset = fault_buffer_entry->offset;

      skiplist_delete(&addr_list, fault_buffer_entry->lookup);

      if (first_buffer_entry.len <= OPT_THRESHOLD) {
        copy_dst =
            first_buffer_entry.addr + first_buffer_entry.offset - PAGE_SIZE;
        copy_src =
            first_buffer_entry.orig + first_buffer_entry.offset - PAGE_SIZE;
        copy_len = first_buffer_entry.len + PAGE_SIZE;
      } else
        skiplist_insert_entry(&addr_list, &first_buffer_entry);
    } else if (fault_buffer_entry->addr + fault_buffer_entry->offset +
                   fault_buffer_entry->len ==
               fault_addr + PAGE_SIZE) {
      fault_buffer_entry->len -= PAGE_SIZE;

      if (fault_buffer_entry->len <= OPT_THRESHOLD) {
        copy_dst = fault_buffer_entry->addr + fault_buffer_entry->offset;
        copy_src = fault_buffer_entry->orig + fault_buffer_entry->offset;
        copy_len = fault_buffer_entry->len + PAGE_SIZE;

        skiplist_delete(&addr_list, fault_buffer_entry->lookup);
      }
    } else {
      uint64_t offset = fault_addr + PAGE_SIZE - fault_buffer_entry->addr;

      snode second_tracked_buffer;
      second_tracked_buffer.lookup = fault_buffer_entry->addr + offset;
      second_tracked_buffer.orig = fault_buffer_entry->orig + offset;
      second_tracked_buffer.addr = fault_buffer_entry->addr + offset;
      ssize_t second_buf_len =
          fault_buffer_entry->len -
          (uint64_t)(fault_addr - fault_buffer_entry->addr -
                     fault_buffer_entry->offset) -
          PAGE_SIZE;

      if (second_buf_len < 0) {
        fprintf(stderr, "invalid length\n");
        abort();
      }

      second_tracked_buffer.len = second_buf_len;
      second_tracked_buffer.offset = 0;

      ssize_t first_buf_len =
          fault_buffer_entry->len - (second_tracked_buffer.len + PAGE_SIZE);

      if (first_buf_len < 0) {
        fprintf(stderr, "invalid length\n");
        abort();
      }

      fault_buffer_entry->len = first_buf_len;

      if (fault_buffer_entry->len <= OPT_THRESHOLD) {
        copy_dst = fault_buffer_entry->addr + fault_buffer_entry->offset;
        copy_src = fault_buffer_entry->orig + fault_buffer_entry->offset;
        copy_len = fault_buffer_entry->len + PAGE_SIZE;

        skiplist_delete(&addr_list, fault_buffer_entry->lookup);
      }

      if (second_tracked_buffer.len <= OPT_THRESHOLD)
        copy_len += second_tracked_buffer.len;
      else
        skiplist_insert_entry(&addr_list, &second_tracked_buffer);
    }

    LOG("[%s] copy from the original: %p-%p -> %p-%p, len: %lu\n", __func__,
        copy_src, copy_src + copy_len, copy_dst, copy_dst + copy_len, copy_len);

    mmapcpy(copy_dst, copy_src, copy_len);

    LOG("[%s] copy is done. There might be another page fault unless this is "
        "shown\n",
        __func__);
  }

  struct uffdio_range range;
  range.start = fault_addr;
  range.len = PAGE_SIZE;

  num_faults++;

  if (ioctl(uffd, UFFDIO_WAKE, &range) < 0) {
    printf("[%s] range.start: %p, range.len: %lu\n", __func__, range.start,
           range.len);
    perror("uffdio wake");
    assert(0);
  }
}

void *handle_fault() {
  static struct uffd_msg msg[MAX_UFFD_MSGS];
  ssize_t nread;
  uint64_t fault_addr;
  uint64_t fault_flags;
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

    // LOG("waking for page fault?\n");

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

    nread = read(uffd, &msg[0], MAX_UFFD_MSGS * sizeof(struct uffd_msg));
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
    for (i = 0; i < nmsgs; ++i) {
      if (msg[i].event & UFFD_EVENT_PAGEFAULT) {
        // LOG("page fault event\n");
        fault_addr = (uint64_t)msg[i].arg.pagefault.address;
        fault_flags = msg[i].arg.pagefault.flags;

        if (fault_flags & UFFD_PAGEFAULT_FLAG_WP) {
          LOG("[%s] The original buffer is touched\n", __func__);
          printf("caught a write-protected page fault\n");

          // TODO: Currently, entire buffer is being copied, need to do
          // page-by-page
          copy_from_original(fault_addr);

          struct uffdio_writeprotect wp;
          wp.range.start = (uint64_t)PAGE_ALIGN_DOWN(fault_addr);
          wp.range.len = PAGE_SIZE;
          if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
            perror("Set write protection fail");
            abort();
          }

        } else {
          LOG("[%s] handling fault at %p\n", __func__, fault_addr);

          handle_missing_fault((void *)fault_addr);
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

skiplist alloc_list;

void NewHook(const void *ptr, size_t size) {
  if (size > OPT_THRESHOLD) {
    snode entry;
    entry.lookup = (uint64_t)ptr;
    entry.len = size;
    skiplist_insert_entry(&alloc_list, &entry);

    /*
    LOG("[%s] ptr: %p len: %zu malloced\n",
        __func__, ptr, size);
    void *p = ptr + LEFT_FRINGE_LEN(ptr);
    ssize_t remaining_len = size;
    while (remaining_len > OPT_THRESHOLD) {
      snode *exist = skiplist_search(&addr_list, p);
      if (exist) {
        if (exist->addr == exist->orig) { // original
          //copy_from_original(exist->orig);
        } else {
          UNREGISTER_FAULT(exist->addr + exist->offset, exist->len);
        }

        p += exist->len;
        remaining_len -= exist->len;

        skiplist_delete(&addr_list, exist->lookup);
      } else {
        p += PAGE_SIZE;
        remaining_len -= PAGE_SIZE;
      }
    }
    */
  }
}

void DeleteHook(const void *ptr) {
  snode *alloc_entry = skiplist_search(&alloc_list, ptr);
  if (alloc_entry) {
    ssize_t remaining_len = alloc_entry->len;
    void *p = ptr + LEFT_FRINGE_LEN(ptr);
#if ENABLED_LOCK
    pthread_mutex_lock(&mu);
#endif
    while (remaining_len > OPT_THRESHOLD) {
      snode *exist = skiplist_search(&addr_list, p);
      if (exist) {
        LOG("[%s] ptr: %p\n", __func__, ptr);
        if (exist->addr == exist->orig) {
          copy_from_original(exist->orig);
        } else {
          UNREGISTER_FAULT(exist->addr + exist->offset, exist->len);
        }
        skiplist_delete(&addr_list, exist->lookup);

        p += exist->len;
        remaining_len -= exist->len;
      } else {
        p += PAGE_SIZE;
        remaining_len -= PAGE_SIZE;
      }
    }
#if ENABLED_LOCK
    pthread_mutex_unlock(&mu);
#endif
    skiplist_delete(&alloc_list, alloc_entry);
  }
}

void init_tcmalloc_hook() {
  skiplist_init(&alloc_list);
  assert(MallocHook_AddNewHook(&NewHook));
  assert(MallocHook_AddDeleteHook(&DeleteHook));
}

void destroy_hook() {
  assert(MallocHook_RemoveNewHook(&NewHook));
  assert(MallocHook_RemoveDeleteHook(&DeleteHook));
}

static void init(void) {
  fprintf(stdout, "zIO start\n");

  libc_pwrite = bind_symbol("pwrite");
  libc_pwritev = bind_symbol("pwritev");
  libc_memcpy = bind_symbol("memcpy");
  libc_memmove = bind_symbol("memmove");
  libc_free = bind_symbol("free");
  libc_send = bind_symbol("send");
  libc_sendmsg = bind_symbol("sendmsg");
  libc_recv = bind_symbol("recv");
  libc_recvmsg = bind_symbol("recvmsg");

  // new tracking code
  skiplist_init(&addr_list);

  init_tcmalloc_hook();

#if ENABLED_LOCK
  pthread_mutex_init(&mu, NULL);
#endif

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
  uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
  // 0; //  |  UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_PAGEFAULT_FLAG_WP|
  //  UFFD_FEATURE_MISSING_HUGETLBFS;// | UFFD_FEATURE_EVENT_UNMAP |
  //  UFFD_FEATURE_EVENT_REMOVE;
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
