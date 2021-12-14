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

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK ~(PAGE_SIZE - 1)  // 0xfffffffff000

#define MAX_UFFD_MSGS 1

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

#define MIN(x, y) (x < y ? x : y)

#define IS_ALIGNED(addr) ((uint64_t)addr % PAGE_MASK == 0)
#define PAGE_ALIGN_DOWN(addr) ((void *)((uint64_t)addr & PAGE_MASK))
#define PAGE_ALIGN_UP(addr) \
  ((void *)((uint64_t)PAGE_ALIGN_DOWN(addr) + PAGE_SIZE))
#define LEFT_FRINGE_LEN(addr) \
  (((uint64_t)PAGE_ALIGN_UP(addr) - (uint64_t)addr) % PAGE_SIZE)

#define REGISTER_FAULT(reg_start, reg_len)                      \
  do {                                                          \
    struct uffdio_register uffdio_register;                     \
    uffdio_register.range.start = (uint64_t)reg_start;          \
    uffdio_register.range.len = (uint64_t)reg_len;              \
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;        \
    uffdio_register.ioctls = 0;                                 \
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) { \
      fprintf(stderr, "%d: ", __LINE__);                        \
      perror("ioctl uffdio_register");                          \
      abort();                                                  \
    }                                                           \
  } while (0)

#define UNREGISTER_FAULT(reg_start, reg_len)                        \
  do {                                                              \
    struct uffdio_range uffdio_unregister;                          \
    uffdio_unregister.start = (uint64_t)reg_start;                  \
    uffdio_unregister.len = (uint64_t)reg_len;                      \
    if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) { \
      fprintf(stderr, "%d: ", __LINE__);                            \
      perror("ioctl uffdio_unregister");                            \
      abort();                                                      \
    }                                                               \
  } while (0)

long uffd = -1;

pthread_t fault_thread, stats_thread;

static inline void ensure_init(void);

// struct addr_encoding {
//   uint64_t addr;
//   uint32_t len;
//   uint64_t code;
//   uint8_t bytes[64];
// };

// struct addr_track {
//   uint64_t last_addr;
//   uint64_t original;
//   uint16_t size;
// };

// struct addr_track roll_addr[2048];

uint64_t num_fast_writes, num_slow_writes, num_fast_copy, num_slow_copy,
    num_faults;

/* Function pointers to the libc functions */
// static int (*libc_socket)(int domain, int type, int protocol) = NULL;
// static int (*libc_close)(int sockfd) = NULL;
// static int (*libc_shutdown)(int sockfd, int how) = NULL;
// static int (*libc_bind)(int sockfd, const struct sockaddr *addr,
//                         socklen_t addrlen) = NULL;
// static int (*libc_connect)(int sockfd, const struct sockaddr *addr,
//                            socklen_t addrlen) = NULL;
// static int (*libc_listen)(int sockfd, int backlog) = NULL;
// static int (*libc_accept4)(int sockfd, struct sockaddr *addr,
//                            socklen_t *addrlen, int flags) = NULL;
// static int (*libc_accept)(int sockfd, struct sockaddr *addr,
//                           socklen_t *addrlen) = NULL;
// static int (*libc_fcntl)(int sockfd, int cmd, ...) = NULL;
// static int (*libc_getsockopt)(int sockfd, int level, int optname, void
// *optval,
//                               socklen_t *optlen) = NULL;
// static int (*libc_setsockopt)(int sockfd, int level, int optname,
//                               const void *optval, socklen_t optlen) = NULL;
// static int (*libc_getsockname)(int sockfd, struct sockaddr *addr,
//                                socklen_t *addrlen) = NULL;
// static int (*libc_getpeername)(int sockfd, struct sockaddr *addr,
//                                socklen_t *addrlen) = NULL;
// static ssize_t (*libc_read)(int fd, void *buf, size_t count) = NULL;
// static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len,
//                             int flags) = NULL;
// static ssize_t (*libc_recvfrom)(int sockfd, void *buf, size_t len, int flags,
//                                 struct sockaddr *src_addr,
//                                 socklen_t *addrlen) = NULL;
// static ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg,
//                                int flags) = NULL;
// static ssize_t (*libc_readv)(int sockfd, const struct iovec *iov,
//                              int iovcnt) = NULL;
// static ssize_t (*libc_write)(int fd, const void *buf, size_t count) = NULL;
// static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len,
//                             int flags) = NULL;
// static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len,
//                               int flags, const struct sockaddr *dest_addr,
//                               socklen_t addrlen) = NULL;
// static ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg,
//                                int flags) = NULL;
// static ssize_t (*libc_writev)(int sockfd, const struct iovec *iov,
//                               int iovcnt) = NULL;
// static int (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
//                           fd_set *exceptfds, struct timeval *timeout) = NULL;
// static int (*libc_pselect)(int nfds, fd_set *readfds, fd_set *writefds,
//                            fd_set *exceptfds, const struct timespec *timeout,
//                            const sigset_t *sigmask) = NULL;

// static void *(*libc_memset)(void *ptr, int value, size_t num);

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset) = NULL;
static void *(*libc_realloc)(void *ptr, size_t new_size);
static void (*libc_free)(void *ptr);

skiplist addr_list;

void print_trace(void) {
  char **strings;
  size_t i, size;
  enum Constexpr { MAX_SIZE = 1024 };
  void *array[MAX_SIZE];
  size = backtrace(array, MAX_SIZE);
  strings = backtrace_symbols(array, size);
  for (i = 0; i < 5; i++) LOG("%s\n", strings[i]);
  libc_free(strings);
}

// ssize_t read(int sockfd, void *buf, size_t count) {
//   ssize_t ret = 0;
//   static void *prev_addr, *prev_orig;  //, *max_addr;
//   static size_t prev_len;
//   uint64_t original;
//   ensure_init();

//   const int can_call_recv = (count > OPT_THRESHOLD);

//   if (can_call_recv) {
//     ret = libc_recv(sockfd, buf, count, MSG_WAITALL);
//   } else {
//     ret = libc_read(sockfd, buf, count);
//   }

//   const int read_error = (ret == -1);
//   if (read_error) {
//     perror("linux read");
//     return ret;
//   }

//   // do {
//   // ret = libc_read(sockfd, buf, count);
//   // if (ret == -1 && errno != EAGAIN) {
//   // perror("linux read");
//   // return ret;
//   // }
//   // } while (errno == EAGAIN);

//   LOG("tas read %zu bytes, page mask %lx, socket %d\n", ret,
//       ((uint64_t)buf) & PAGE_MASK, sockfd);

//   const int can_optimize = (ret > OPT_THRESHOLD);
//   if (can_optimize) {
//     LOG("reading from network at %p, size %zu, key %lx, original %p\n", buf,
//         ret, ((uint64_t)buf) & PAGE_MASK, (uint64_t)buf);

//     skiplist_insert(&addr_list, ((uint64_t)buf) & PAGE_MASK, (uint64_t)buf,
//                     count, 0);
//   }

//   return ret;

// #if 0
//     // TODO: What is roll_addr?
//     // LOG("returned addr %p, highest so far %p\n", original, max_addr);
//     LOG("old roll_addr %p, prev_addr %p, prev_len %zu\n",
//         roll_addr[sockfd].last_addr, prev_addr, prev_len);
//     if ((((uint64_t)prev_addr + prev_len) & PAGE_MASK) ==
//             (((uint64_t)buf) & PAGE_MASK) &&
//         prev_len) {
//       // roll_addr[sockfd].last_addr = (uint64_t) prev_addr + prev_len;
//       roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
//       roll_addr[sockfd].size = prev_len + ret;
//       roll_addr[sockfd].original = prev_orig;
//       LOG("small addr found\n");
//     } else {
//       if (roll_addr[sockfd].last_addr == (uint64_t)buf) {
//         roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
//         roll_addr[sockfd].size += ret;
//         LOG("rolling, old original %p new original %p\n",
//             roll_addr[sockfd].original, buf);
//       } else {
//         roll_addr[sockfd].last_addr = (uint64_t)buf + ret;
//         roll_addr[sockfd].size = ret;
//         roll_addr[sockfd].original = (uint64_t)buf;
//         LOG("not rolling, size is %zu, should be %zu\n",
//         roll_addr[sockfd].size,
//             ret);
//       }
//       LOG("small addr not found: prev %p, current %p\n",
//           (uint64_t)prev_addr + prev_len, (uint64_t)buf);
//     }

//     uint64_t old_addr =
//         (roll_addr[sockfd].last_addr - roll_addr[sockfd].size) & PAGE_MASK;
//     LOG("new roll_addr %p, size %zu, original %p inserting at %p\n",
//         roll_addr[sockfd].last_addr, roll_addr[sockfd].size, buf, old_addr);
//     skiplist_insert(&addr_list, old_addr, roll_addr[sockfd].original,
//                     roll_addr[sockfd].size, 0);
//   }

//   if (((uint64_t)buf - ret) == prev_addr) {
//     prev_len += ret;
//   } else {
//     prev_addr = buf;
//     prev_len = ret;
//     prev_orig = buf;
//   }

//   return ret;
// #endif
// }

// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
//   ensure_init();

//   ssize_t ret = libc_recvmsg(sockfd, msg, flags);

//   int i;
//   for (i = 0; i < msg->msg_iovlen; i++) {
//     uint64_t target_addr = (uint64_t)msg->msg_iov[i].iov_base;
//     uint64_t target_len = msg->msg_iov[i].iov_len;
//     uint64_t target_aligned_addr = target_addr & PAGE_MASK;

//     uint64_t core_buffer_addr = (target_addr == target_aligned_addr)
//                                     ? target_aligned_addr
//                                     : target_aligned_addr + PAGE_SIZE;
//     uint64_t left_fringe_len = core_buffer_addr - target_addr;
//     uint64_t core_buffer_len = target_len - left_fringe_len;

//     if (target_len > OPT_THRESHOLD) {
//       snode *entry = skiplist_search(&addr_list, target_aligned_addr);
//       if (entry == NULL) {
//         skiplist_insert_with_core_addr(&addr_list, target_aligned_addr,
//                                        target_addr, core_buffer_addr,
//                                        core_buffer_len, left_fringe_len);

//         // mmap(core_buffer_addr, core_buffer_len, PROT_READ | PROT_WRITE,
//         //      MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

//         struct uffdio_register uffdio_register;
//         uffdio_register.range.start = core_buffer_addr;
//         uffdio_register.range.len = (core_buffer_len / PAGE_SIZE) *
//         PAGE_SIZE; uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
//         uffdio_register.ioctls = 0;

//         LOG("[%s] uffd registering addr %p-%p, len %zu\n", __func__,
//             uffdio_register.range.start,
//             uffdio_register.range.start + uffdio_register.range.len,
//             uffdio_register.range.len);
//         if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
//           perror("ioctl uffdio_register");
//           abort();
//         }

//         LOG("[%s] insert %p(%p) len: %lu into skiplist\n", __func__,
//             target_aligned_addr, target_addr, core_buffer_len);
//       } else {
//         // update the entry
//         entry->orig = target_addr;
//         entry->core = core_buffer_addr;
//         entry->len = core_buffer_len;
//         entry->offset = left_fringe_len;
//       }
//     }
//   }

//   return ret;
// }

// ssize_t write(int sockfd, const void *buf, size_t count) {
//   ensure_init();

//   ssize_t ret = 0;

//   const int cannot_optimize = (count <= OPT_THRESHOLD);

//   if (cannot_optimize) {
//     return libc_write(sockfd, buf, count);
//   }

//   snode *entry = skiplist_search(&addr_list, ((uint64_t)buf) & PAGE_MASK);
//   LOG("writing to linux from %p, bounded %p, size %zu, entry %p\n", buf,
//       ((uint64_t)buf) & PAGE_MASK, count, entry);

//   if (!entry) {
//     LOG("slow write !!! entry %p not found\n", buf);

//     num_slow_writes++;
//     return libc_write(sockfd, buf, count);
//   }

//   // clean up old skiplist entry

//   uint64_t src_bounded = ((uint64_t)buf) & PAGE_MASK;
//   uint32_t register_len = (count & PAGE_MASK) - PAGE_SIZE;

//   struct uffdio_range uffdio_unregister;
//   uffdio_unregister.start = src_bounded + PAGE_SIZE;
//   uffdio_unregister.len = register_len;

//   LOG("uffd unregistering addr %p-%p, len %zu\n", src_bounded + PAGE_SIZE,
//       src_bounded + PAGE_SIZE + register_len, register_len);

//   const int unregister_failed =
//       (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1);

//   if (unregister_failed) {
//     perror("ioctl uffdio_unregister");
//     abort();
//   }

//   num_fast_writes++;

//   skiplist_delete(&addr_list, ((uint64_t)buf) & PAGE_MASK);
//   LOG("write from %p len %zu out of %zu\n", entry->orig, entry->len, count);

//   ret = libc_write(sockfd, (const void *)entry->orig, count);

//   LOG("actually wrote %zu\n", ret);

//   return ret;
// }

void _pwrite_data(const snode *node, struct write_args_t *args) {
  // Assume that args->buf is already page aligned
  const char can_write =
      (node->addr + node->offset <= (uint64_t)args->buf &&
       (uint64_t)args->buf < node->addr + node->offset + node->len);

  if (can_write) {
    size_t bytes_to_write =
        MIN(args->count, (uint64_t)PAGE_ALIGN_DOWN(node->len));
    libc_pwrite(args->fd, (const void *)(node->orig + node->offset),
                bytes_to_write, args->offset);
    args->buf += bytes_to_write;
    args->count -= bytes_to_write;
    args->offset += bytes_to_write;

    LOG("[%s] fd %d buf %p count %zu offset %ld\n", __func__, args->fd,
        node->orig + node->offset, bytes_to_write, args->offset);

    if (args->count < PAGE_SIZE) {
      args->stop = 1;
    }
  }
}

ssize_t pwrite(int sockfd, const void *buf, size_t count, off_t offset) {
  ensure_init();

  ssize_t ret = 0;

  const int cannot_optimize = (count <= OPT_THRESHOLD);

  if (cannot_optimize) {
    return libc_pwrite(sockfd, buf, count, offset);
  }

  // TODO: pwrite at a time?
  // TODO: optimize the code below

  snode *entry = skiplist_search(&addr_list, (uint64_t)PAGE_ALIGN_DOWN(buf));
  if (!entry) {
    num_slow_writes++;
    return libc_pwrite(sockfd, buf, count, offset);
  }

  void *buf_ptr = (void *)entry->addr;
  size_t remaining = MIN(count, entry->len);

  if (entry->offset > 0) {
    libc_pwrite(sockfd, buf_ptr, entry->offset, offset);
    offset += entry->offset;
    buf_ptr += entry->offset;
    remaining -= entry->offset;
  }

  struct write_args_t args;
  args.fd = sockfd;
  args.buf = buf_ptr;
  args.count = remaining;
  args.offset = offset;
  args.stop = 0;

  skiplist_walkthrough_write(&addr_list, _pwrite_data, &args);

  size_t written_bytes = args.offset - offset;
  offset += written_bytes;
  buf_ptr += written_bytes;
  remaining -= written_bytes;

  if (remaining > 0) {
    if (remaining > PAGE_SIZE) {
      fprintf(stderr,
              "the remaining size %zu cannot be larger than the page size\n",
              remaining);
      abort();
    }

    printf("write the remaining\n");
    libc_pwrite(sockfd, buf_ptr, remaining, offset);
  }

  num_fast_writes++;

  return count;
}

void *memcpy(void *dest, const void *src, size_t n) {
  ensure_init();

  static uint64_t prev_start, prev_end;
  // TODO: parse big copy for multiple small copies

  const char cannot_optimize = (n <= OPT_THRESHOLD);

  if (cannot_optimize) {
    return libc_memcpy(dest, src, n);
  }

  const void *src_aligned_addr = PAGE_ALIGN_DOWN(src);

  LOG("[%s] copying %p-%p to %p-%p, size %zu\n", __func__, src, src + n, dest,
      dest + n, n);
  // skiplist_dump(&addr_list);

  snode *src_entry = skiplist_search(&addr_list, (uint64_t)src_aligned_addr);
  const char is_no_src = (src_entry == NULL);
  snode new_entry;
  if (is_no_src) {
    LOG("[%s] %p appears first time --> store to skiplist\n", __func__, src);

    new_entry.lookup = (uint64_t)src_aligned_addr;
    new_entry.orig = (uint64_t)src;
    new_entry.addr = (uint64_t)src;
    new_entry.len = n;
    new_entry.offset = LEFT_FRINGE_LEN(src);
    skiplist_insert_entry(&addr_list, &new_entry);

#if LOGON
    LOG("[%s] insert src entry\n", __func__);
    snode_dump(&new_entry);
#endif

    src_entry = &new_entry;
  }

  const char should_remap_readonly = src_entry->addr == src_entry->orig;
  if (should_remap_readonly) {
    void *core_buffer_addr = (void *)(src_entry->addr + src_entry->offset);
    size_t right_fringe_len = (src_entry->len - src_entry->offset) % PAGE_SIZE;
    size_t core_buffer_len =
        src_entry->len - src_entry->offset - right_fringe_len;

    mprotect(core_buffer_addr, core_buffer_len, PROT_READ);

    // TODO: A certain kernel version is required
    // struct uffdio_register uffdio_register;
    // uffdio_register.range.start = (uint64_t)core_buffer_addr;
    // uffdio_register.range.len = core_buffer_len;
    // uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
    // uffdio_register.ioctls = 0;

    // if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    //   perror("ioctl uffdio_register");
    //   abort();
    // }

    // struct uffdio_writeprotect wp;
    // wp.range.start = uffdio_register.range.start;
    // wp.range.len = uffdio_register.range.len;
    // wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    // if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
    //   perror("Set write protection fail");
    //   abort();
    // }

    LOG("[%s] uffd read-only registering addr %p-%p, len %zu\n", __func__,
        core_buffer_addr, core_buffer_addr + core_buffer_len, core_buffer_len);
  }

  // TODO: If the destination location is within a buffer already tracked in the
  // skiplist, the skiplist entry is updated with the new buffer information.

  snode dest_entry;
  dest_entry.lookup = (uint64_t)PAGE_ALIGN_DOWN(dest);
  dest_entry.orig = src_entry->orig;
  dest_entry.addr = (uint64_t)dest;
  dest_entry.len = n;
  dest_entry.offset = LEFT_FRINGE_LEN(dest);

  snode *entry = 0;
  const char is_dest_exist =
      (entry = skiplist_search(&addr_list, dest_entry.lookup)) != NULL;
  if (is_dest_exist) {
    entry->lookup = dest_entry.lookup;
    entry->orig = dest_entry.orig;
    entry->addr = dest_entry.addr;
    entry->len = dest_entry.len;
    entry->offset = dest_entry.offset;
    entry->free = dest_entry.free;
    LOG("[%s] update dest entry\n", __func__);
  } else {
    skiplist_insert_entry(&addr_list, &dest_entry);
    LOG("[%s] insert dest entry\n", __func__);
  }

#if LOGON
  snode_dump(&dest_entry);
#endif

  void *dest_core_buffer_addr =
      (void *)((uint64_t)dest_entry.addr + dest_entry.offset);
  size_t dest_right_fringe_len =
      (dest_entry.len - dest_entry.offset) % PAGE_SIZE;
  size_t dest_core_buffer_len =
      dest_entry.len - dest_entry.offset - dest_right_fringe_len;

  mmap(dest_core_buffer_addr, dest_core_buffer_len, PROT_READ | PROT_WRITE,
       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

  REGISTER_FAULT(dest_core_buffer_addr, dest_core_buffer_len);

  LOG("[%s] uffd registering addr %p-%p, len %zu\n", __func__,
      dest_core_buffer_addr, dest_core_buffer_addr + dest_core_buffer_len,
      dest_core_buffer_len);

  if (dest_entry.offset > 0)
    libc_memcpy((void *)dest_entry.addr, (const void *)src_entry->orig,
                dest_entry.offset);

  if (dest_right_fringe_len > 0)
    libc_memcpy(
        (void *)(dest_entry.addr + dest_entry.len - dest_right_fringe_len),
        (const void *)(src_entry->orig + MIN(src_entry->len, dest_entry.len) -
                       dest_right_fringe_len),
        dest_right_fringe_len);

  num_fast_copy++;

  return dest;

  //   void *src_ptr = src;
  //   void *dest_ptr = dest;

  //   const uint64_t src_left_fringe_len = src_entry->offset;
  //   const int should_copy_left_fringe = src_left_fringe_len > 0;

  //   if (should_copy_left_fringe) {
  //     LOG("[%s] Left fringe copy %lu\n", __func__, src_left_fringe_len);

  //     const uint64_t dest_left_fringe_len = LEFT_FRINGE_LEN(dest);
  //     const char can_copy_on_next_page =
  //         (dest_left_fringe_len == 0 ||
  //          src_left_fringe_len < dest_left_fringe_len);
  //     if (can_copy_on_next_page) {
  //       libc_memcpy(PAGE_ALIGN_UP(dest) - src_left_fringe_len,
  //       src_entry->addr,
  //                   src_left_fringe_len);
  //       dest_ptr = PAGE_ALIGN_UP(dest);
  //     } else {
  //       // XXX: Does dest buffer have enough space?
  //       libc_memcpy(PAGE_ALIGN_UP(dest) + PAGE_SIZE - src_left_fringe_len,
  //                   src_entry->addr, src_left_fringe_len);
  //       dest_ptr = PAGE_ALIGN_UP(dest) + PAGE_SIZE;
  //     }

  //     src_ptr += src_left_fringe_len;
  //     n -= src_left_fringe_len;
  //   }

  //   size_t core_buffer_len = n - (n % PAGE_SIZE);

  //   mmap(dest_ptr, core_buffer_len, PROT_READ | PROT_WRITE,
  //        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

  //   struct uffdio_register uffdio_register;
  //   uffdio_register.range.start = dest_ptr;
  //   uffdio_register.range.len = core_buffer_len;
  //   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  //   uffdio_register.ioctls = 0;

  //   LOG("[%s] uffd registering addr %p-%p, len %zu\n", __func__,
  //       uffdio_register.range.start,
  //       uffdio_register.range.start + uffdio_register.range.len,
  //       uffdio_register.range.len);
  //   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
  //     perror("ioctl uffdio_register");
  //     abort();
  //   }

  //   src_ptr += core_buffer_len;
  //   dest_ptr += core_buffer_len;
  //   n -= core_buffer_len;

  //   if (n > 0) {
  //     LOG("[%s] copy remaining bytes %zu\n", __func__, n);
  //     libc_memcpy(dest_ptr, src_ptr, n);
  //   }

  //   skiplist_insert_entry(&addr_list, &dest_entry);

  // #if LOGON
  //   LOG("[%s] insert dest entry\n", __func__);
  //   snode_dump(&dest_entry);
  // #endif

  //   num_fast_copy++;

  //   return dest;
}

void free(void *ptr) {
  // uint64_t ptr_bounded = (uint64_t)ptr & PAGE_MASK;
  // snode *entry = skiplist_search(&addr_list, ptr_bounded);

  // if (entry) {
  //   if (entry->orig == ptr) {
  //     // mark for later free
  //     entry->free = 1;
  //     return;
  //   } else {
  //     skiplist_delete(&addr_list, ptr_bounded);
  //   }
  // }
  // return libc_free(ptr);
}

void *realloc(void *ptr, size_t new_size) {
  ensure_init();

  // LOG("[%s] %p (%p)\n", __func__, ptr, ((uint64_t)ptr) & PAGE_MASK);

  int cannot_optimize = (new_size <= OPT_THRESHOLD || ptr == NULL);

  if (cannot_optimize) {
    // LOG("[%s] (%zu <= OPT_THRESHOLD || ptr == NULL)\n", __func__, new_size);
    return libc_realloc(ptr, new_size);
  }

  snode *entry = skiplist_search(&addr_list, ((uint64_t)ptr) & PAGE_MASK);
  cannot_optimize = (entry == NULL);

  if (cannot_optimize) {
    // LOG("[%s] entry %p not found\n", __func__, ((uint64_t)ptr) & PAGE_MASK);
    return libc_realloc(ptr, new_size);
  }

  LOG("[%s] ptr: %p, size: %zu\n", __func__, ptr, new_size);

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

  // FIXME: realloc may not need to copy data and be handled as a new buffer

  libc_memcpy(new_ptr, entry->orig, entry->len);

  uint64_t new_ptr_bounded = (uint64_t)PAGE_ALIGN_DOWN(new_ptr);
  uint64_t offset = LEFT_FRINGE_LEN(new_ptr);

  snode new_entry;
  new_entry.lookup = new_ptr_bounded;

  new_entry.orig = (uint64_t)new_ptr;  // entry->orig;

  new_entry.addr = (uint64_t)new_ptr;
  new_entry.len = new_size;
  new_entry.offset = offset;

  // LOG("[%s] mmaping for uffd at %p, length %zu\n", __func__, new_entry.addr,
  //     new_entry.len);
  // uint64_t mapped_addr = (uint64_t)mmap(
  //     (void *)new_entry.addr, PAGE_ALIGN_DOWN(new_entry.len), PROT_READ |
  //     PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  // if (mapped_addr != new_entry.addr) {
  //   fprintf(stderr, "bad mmap return %p... parameters %p, %zu\n", ret,
  //           new_entry.addr, new_entry.len);
  //   perror("memcpy mmap");
  //   abort();
  // }

  // REGISTER_FAULT(new_entry.addr, PAGE_ALIGN_DOWN(new_entry.len));

  // LOG("[%s] successfully mapped and registered %p\n", __func__,
  // new_entry.addr); LOG("[%s] inserting original %p at location %p\n",
  // __func__, entry->orig,
  //     new_ptr_bounded);

  // mprotect(new_entry.addr + new_entry.offset, PAGE_ALIGN_DOWN(new_entry.len -
  // new_entry.offset), PROT_READ);
  skiplist_insert_entry(&addr_list, &new_entry);

  LOG("[%s] a new entry\n", __func__);
#if LOGON
  snode_dump(&new_entry);
#endif

  // print_trace();

  return new_ptr;
}

#if USED
void *memmove(void *dest, const void *src, size_t n) {
  ensure_init();
  if (n > OPT_THRESHOLD) {
    LOG("[%s] moving %p to %p, size %zu\n", __func__, src, dest, n);
    // return dest;
  } else if (n > 1024)
    ;
  // LOG("sizeable, but not large enough move from %p to %p of size %zu\n",
  // dest,
  //     src, n);
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

void copy_from_original(snode *entry, struct fault_copy_args_t *args) {
  {
    fprintf(stderr, "%s Need to be implmented\n", __func__);
    abort();
  }

  // args->original_entry is the original
  LOG("[%s] entry->orig: %p, args->original_entry->addr: %p\n", __func__,
      entry->orig, args->original_entry->addr);

  const char is_related_to_original = entry->orig == args->original_entry->addr;
  if (is_related_to_original) {
    const char is_original_buffer = entry->addr == args->original_entry->addr;

    if (is_original_buffer) {
      LOG("[%s] This buffer is the original\n", __func__);
      return;
    }

    LOG("[%s] This buffer should be updated\n", __func__);
#if LOGON
    snode_dump(entry);
#endif

    void *src_ptr = PAGE_ALIGN_DOWN(args->fault_addr);
    uint64_t offset_to_page = src_ptr - args->original_entry->addr;

    void *dest_target_addr = entry->addr + offset_to_page;
    uint64_t dest_aligned_target_addr =
        PAGE_ALIGN_DOWN(entry->addr + offset_to_page);

    src_ptr -= dest_target_addr - dest_aligned_target_addr;

    size_t mapping_len = dest_target_addr == dest_aligned_target_addr
                             ? PAGE_SIZE
                             : 2 * PAGE_SIZE;
    void *ret =
        mmap(dest_aligned_target_addr, mapping_len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);

    const char is_map_failed =
        (ret == MAP_FAILED || dest_aligned_target_addr != ret);
    if (is_map_failed) {
      fprintf(stderr, "in: %p, out: %p\n", dest_aligned_target_addr, ret);
      perror("failed to handle missing fault");
      abort();
    }

    LOG("[%s] copy touched page %p -> %p\n", __func__, src_ptr,
        dest_aligned_target_addr);

    libc_memcpy((void *)dest_aligned_target_addr, src_ptr, mapping_len);

    const char is_first_page =
        (entry->addr + entry->offset == dest_aligned_target_addr);
    if (is_first_page) {
      LOG("[%s] delete the entry %p\n", __func__, entry->lookup);

      skiplist_delete(&addr_list, entry->lookup);

      snode new_entry;
      new_entry.lookup = dest_aligned_target_addr + mapping_len;
      new_entry.orig = (uint64_t)src_ptr + mapping_len;
      new_entry.addr = dest_aligned_target_addr + mapping_len;
      new_entry.len = entry->addr + entry->len - new_entry.addr + 1;
      new_entry.offset = 0;

      if (new_entry.len > OPT_THRESHOLD) {
        LOG("[%s] Add the fault page %p to skiplist\n", __func__,
            new_entry.lookup);

        skiplist_insert_entry(&addr_list, &new_entry);
      }

    } else {
      snode new_entry;
      new_entry.lookup = dest_aligned_target_addr + mapping_len;
      new_entry.orig = (uint64_t)src_ptr + mapping_len;
      new_entry.addr = dest_aligned_target_addr + mapping_len;
      new_entry.len = entry->addr + entry->len - new_entry.addr;
      new_entry.offset = 0;

      LOG("[%s] update the entry %p: len %lu -> %lu\n", __func__, entry->lookup,
          entry->len, entry->len - new_entry.len - mapping_len);

      LOG("[%s] The first part is updated yet\n", __func__);
#if LOGON
      snode_dump(entry);
#endif

      entry->len -= new_entry.len + mapping_len;

      LOG("[%s] The first part is updated\n", __func__);
#if LOGON
      snode_dump(entry);
#endif

      if (new_entry.len > OPT_THRESHOLD) {
        LOG("[%s] Add new second part to skiplist\n", __func__);
#if LOGON
        snode_dump(&new_entry);
#endif

        skiplist_insert_entry(&addr_list, &new_entry);
      }
    }
  }
}

void handle_missing_fault(void *fault_addr) {
  void *fault_page_start_addr = PAGE_ALIGN_DOWN(fault_addr);

  snode *fault_buffer_entry =
      skiplist_search_buffer_fallin(&addr_list, (uint64_t)fault_addr);
  if (!fault_buffer_entry) {
    fprintf(stderr, "[%s:%d] invalid codepath\n", __func__, __LINE__);
    abort();
  }

  LOG("Fault entry\n");
#if LOGON
  snode_dump(fault_buffer_entry);
#endif

  UNREGISTER_FAULT(
      fault_buffer_entry->addr + fault_buffer_entry->offset,
      PAGE_ALIGN_DOWN(fault_buffer_entry->len - fault_buffer_entry->offset));

  void *ret =
      mmap(fault_page_start_addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);

  const char is_map_failed =
      (ret == MAP_FAILED || fault_page_start_addr != ret);
  if (is_map_failed) {
    perror("failed to handle missing fault");
    abort();
  }

  const void *src_ptr = (void *)(fault_buffer_entry->orig +
                                 (fault_page_start_addr - fault_buffer_entry->addr));

  // FIXME: memcpy is freezing
  LOG("[%s] will copy touched page %p -> %p(fault_buffer_entry->orig: %p)\n",
      __func__, src_ptr, fault_page_start_addr, fault_buffer_entry->orig);

#if LOGON
  if (fault_page_start_addr - fault_buffer_entry->addr !=
      src_ptr - fault_buffer_entry->orig) {
    printf("copy wrong place\n");
  }
#endif
  libc_memcpy(fault_page_start_addr, src_ptr, PAGE_SIZE);

  LOG("[%s] copy touched page %p -> %p\n", __func__, src_ptr,
      fault_page_start_addr);

  const char is_first_page =
      (fault_buffer_entry->addr + fault_buffer_entry->offset ==
       (uint64_t)fault_page_start_addr);

  const uint64_t first_part_addr = fault_buffer_entry->addr;
  const size_t first_part_len_before_update = fault_buffer_entry->len;
  if (is_first_page) {
    LOG("[%s] delete the entry %p\n", __func__, fault_buffer_entry->lookup);

    skiplist_delete(&addr_list, fault_buffer_entry->lookup);
  } else {
    LOG("[%s] update the entry %p\n", __func__, fault_buffer_entry->lookup);
    fault_buffer_entry->len =
        (uint64_t)fault_page_start_addr - fault_buffer_entry->addr;

    REGISTER_FAULT(
        fault_buffer_entry->addr + fault_buffer_entry->offset,
        PAGE_ALIGN_DOWN(fault_buffer_entry->len - fault_buffer_entry->offset));
  }

  snode second_part_entry;
  second_part_entry.lookup = (uint64_t)fault_page_start_addr + PAGE_SIZE;
  second_part_entry.orig = (uint64_t)src_ptr + PAGE_SIZE;
  second_part_entry.addr = (uint64_t)fault_page_start_addr + PAGE_SIZE;
  second_part_entry.len =
      first_part_addr + first_part_len_before_update - second_part_entry.addr;
  second_part_entry.offset = 0;

  // TODO: Need to copy data if second_part_entry.len <= OPT_THRESHOLD
  // if (second_part_entry.len > 0) {
  if (second_part_entry.len < PAGE_SIZE) {
    if (second_part_entry.len >= PAGE_SIZE) {
      // mmap(second_part_entry.addr, second_part_entry.len,
      //      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1,
      //      0);
      // libc_memcpy(second_part_entry.addr, second_part_entry.orig,
      //             second_part_entry.len);
    }
  } else {
    LOG("[%s] Add new second part to skiplist\n", __func__);
#if LOGON
    snode_dump(&second_part_entry);
#endif

    skiplist_insert_entry(&addr_list, &second_part_entry);

    REGISTER_FAULT(
        second_part_entry.addr + second_part_entry.offset,
        PAGE_ALIGN_DOWN(second_part_entry.len - second_part_entry.offset));
  }
  // }

  struct uffdio_range range;
  range.start = (uint64_t)fault_page_start_addr;
  range.len = PAGE_SIZE;

  if (ioctl(uffd, UFFDIO_WAKE, &range) < 0) {
    perror("uffdio wake");
    assert(0);
  }
  num_faults++;
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
    for (i = 0; i < nmsgs; i++) {
      if (msg[i].event & UFFD_EVENT_PAGEFAULT) {
        LOG("page fault event\n");
        fault_addr = (uint64_t)msg[i].arg.pagefault.address;
        fault_flags = msg[i].arg.pagefault.flags;

        if (fault_flags & UFFD_PAGEFAULT_FLAG_WP) {
          LOG("[%s] The original buffer is touched\n", __func__);

          snode *original_entry = skiplist_search(
              &addr_list, (uint64_t)PAGE_ALIGN_DOWN(fault_addr));
          if (!original_entry) {
            fprintf(stderr, "invalid codepath\n");
            abort();
          }

          struct fault_copy_args_t args;
          args.original_entry = original_entry;
          args.fault_addr = (void *)fault_addr;
          skiplist_walkthrough_fault_copy(&addr_list, copy_from_original,
                                          &args);

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

static void init(void) {
  fprintf(stdout, "zIO start\n");

  // libc_socket = bind_symbol("socket");
  // libc_close = bind_symbol("close");
  // libc_shutdown = bind_symbol("shutdown");
  // libc_bind = bind_symbol("bind");
  // libc_connect = bind_symbol("connect");
  // libc_listen = bind_symbol("listen");
  // libc_accept4 = bind_symbol("accept4");
  // libc_accept = bind_symbol("accept");
  // libc_fcntl = bind_symbol("fcntl");
  // libc_getsockopt = bind_symbol("getsockopt");
  // libc_setsockopt = bind_symbol("setsockopt");
  // libc_getsockname = bind_symbol("getsockname");
  // libc_getpeername = bind_symbol("getpeername");
  // libc_read = bind_symbol("read");
  // libc_recv = bind_symbol("recv");
  // libc_recvfrom = bind_symbol("recvfrom");
  // libc_recvmsg = bind_symbol("recvmsg");
  // libc_readv = bind_symbol("readv");
  // libc_write = bind_symbol("write");
  // libc_send = bind_symbol("send");
  // libc_sendto = bind_symbol("sendto");
  // libc_sendmsg = bind_symbol("sendmsg");
  // libc_writev = bind_symbol("writev");
  // libc_select = bind_symbol("select");
  // libc_pselect = bind_symbol("pselect");
  // libc_memset = bind_symbol("memset");

  libc_pwrite = bind_symbol("pwrite");
  libc_memcpy = bind_symbol("memcpy");
  libc_memmove = bind_symbol("memmove");
  libc_realloc = bind_symbol("realloc");
  libc_free = bind_symbol("free");

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
