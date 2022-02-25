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
#include <sys/uio.h>
#include <tas_sockets.h>
#include <unistd.h>
#include <utils.h>

//#define OPT_THRESHOLD 0xfffffffffffffffff
#define OPT_THRESHOLD 65535

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK ~(PAGE_SIZE - 1) // 0xfffffffff000

#define MAX_UFFD_MSGS 1024

#define UFFD_PROTO

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

#define MIN(x, y) (x < y ? x : y)

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

#define PWRITE_IOV_MAX_CNT 10000

long uffd = -1;

pthread_t fault_thread, stats_thread;

pthread_mutex_t mu;

static inline void ensure_init(void);

uint64_t num_fast_writes, num_slow_writes, num_fast_copy, num_slow_copy,
    num_faults;

static void *(*libc_memcpy)(void *dest, const void *src, size_t n);
static void *(*libc_memmove)(void *dest, const void *src, size_t n);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count,
                              off_t offset) = NULL;
static ssize_t (*libc_pwritev)(int sockfd, const struct iovec *iov, int iovcnt,
                               off_t offset) = NULL;
static void *(*libc_realloc)(void *ptr, size_t new_size);
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
  for (i = 0; i < 5; i++)
    LOG("%s\n", strings[i]);
  libc_free(strings);
}

void _pwrite_data(const snode *node, struct write_args_t *args) {
  // Assume that args->buf is already page aligned
  if (args->buf + args->buf_off < node->addr + node->len + node->offset) {
    size_t bytes_to_write = MIN(args->len, node->len);

    args->iovec[args->iovcnt].iov_base = node->orig + args->buf_off;
    args->iovec[args->iovcnt].iov_len = bytes_to_write;

    args->iovcnt++;
    args->len -= bytes_to_write;
    args->buf_off += bytes_to_write;

    if (args->len < PAGE_SIZE) {
      args->stop = 1;
    }
  }
}

ssize_t pwrite2(int sockfd, const void *buf, size_t count, off_t offset) {
  ensure_init();

  const int cannot_optimize = (count <= OPT_THRESHOLD);

  if (cannot_optimize) {
    num_slow_writes++;
    return libc_pwrite(sockfd, buf, count, offset);
  }

  pthread_mutex_lock(&mu);

  const uint64_t left_fringe_len = LEFT_FRINGE_LEN(buf);
  const uint64_t right_fringe_len = RIGHT_FRINGE_LEN(count, left_fringe_len);

  struct iovec iovec[PWRITE_IOV_MAX_CNT];
  int iovcnt = 0;

  size_t remaining = count;

  if (left_fringe_len > 0) {
    iovec[iovcnt].iov_base = (void *)buf;
    iovec[iovcnt].iov_len = left_fringe_len;

    iovcnt++;
  }

  uint64_t off = left_fringe_len;
  const uint64_t core_buffer_len = count - (left_fringe_len + right_fringe_len);

  while (off < core_buffer_len) {
    snode *entry = skiplist_search(&addr_list, (uint64_t)buf + off);
    iovec[iovcnt].iov_base =
        (void *)((entry ? entry->orig : (uint64_t)buf) + off);
    iovec[iovcnt].iov_len = PAGE_SIZE;

    off += PAGE_SIZE;

    iovcnt++;

    if (iovcnt >= PWRITE_IOV_MAX_CNT) {
      errno = ENOMEM;
      perror("pwrite iov is full");
      abort();
    }
  }

  if (right_fringe_len > 0) {
    iovec[iovcnt].iov_base = (void *)((uint64_t)buf + count - right_fringe_len);
    iovec[iovcnt].iov_len = right_fringe_len;

    iovcnt++;
  }

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

  num_fast_writes++;

  ssize_t ret = libc_pwritev(sockfd, iovec, iovcnt, offset);

  pthread_mutex_unlock(&mu);

  return ret;
}

void *memcpy(void *dest, const void *src, size_t n) {
  ensure_init();

  static uint64_t prev_start, prev_end;
  // TODO: parse big copy for multiple small copies

  const char cannot_optimize = (n <= OPT_THRESHOLD);

  if (cannot_optimize) {
    return libc_memcpy(dest, src, n);
  }

  pthread_mutex_lock(&mu);

  const void *src_aligned_addr = PAGE_ALIGN_DOWN(src);

  LOG("[%s] copying %p-%p to %p-%p, size %zu\n", __func__, src, src + n, dest,
      dest + n, n);
  // skiplist_dump(&addr_list);

  snode *src_entry = skiplist_search(&addr_list, (uint64_t)src_aligned_addr);
  const char is_no_src = (src_entry == NULL);
  snode new_entry;

  const uint64_t src_left_fringe_len = LEFT_FRINGE_LEN(src);
  const uint64_t src_right_fringe_len =
      RIGHT_FRINGE_LEN(n, src_left_fringe_len);

  const uint64_t dest_left_fringe_len = LEFT_FRINGE_LEN(dest);
  const uint64_t dest_right_fringe_len =
      RIGHT_FRINGE_LEN(n, dest_left_fringe_len);

  if (is_no_src) {
    LOG("[%s] %p appears first time --> store to skiplist\n", __func__, src);

    new_entry.lookup = (uint64_t)src_aligned_addr;
    new_entry.orig = (uint64_t)src;
    new_entry.addr = (uint64_t)src;
    new_entry.len = n - (src_left_fringe_len + src_right_fringe_len);
    new_entry.offset = src_left_fringe_len;

    if (new_entry.len > 0) {
      skiplist_insert_entry(&addr_list, &new_entry);

#if LOGON
      LOG("[%s] insert src entry\n", __func__);
      snode_dump(&new_entry);
#endif
    }

    src_entry = &new_entry;
  }

  if (src_entry->addr == src_entry->orig) {
    // TODO: implment segfault handler for mprotect
    // mprotect(src_entry->addr + src_entry->offset, src_entry->len, PROT_READ);

    // TODO: A specific kernel version is required
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
  }

  // TODO: If the destination location is within a buffer already tracked in the
  // skiplist, the skiplist entry is updated with the new buffer information.

  snode dest_entry;
  dest_entry.lookup = (uint64_t)PAGE_ALIGN_DOWN(dest);
  dest_entry.orig = src_entry->orig;
  dest_entry.addr = (uint64_t)dest;
  dest_entry.len = n - (dest_left_fringe_len + dest_right_fringe_len);
  dest_entry.offset = dest_left_fringe_len;

  snode *entry = 0;
  const char is_tracking_dest =
      (entry = skiplist_search(&addr_list, dest_entry.lookup)) != NULL;
  if (is_tracking_dest) {
    LOG("[%s] the dest buffer exists already\n", __func__);
    skiplist_delete(&addr_list, entry->lookup);

    /* entry->lookup = dest_entry.lookup; */
    /* entry->orig = dest_entry.orig; */
    /* entry->addr = dest_entry.addr; */
    /* entry->len = dest_entry.len; */
    /* entry->offset = dest_entry.offset; */
    /* entry->free = dest_entry.free; */
    /* LOG("[%s] update dest entry\n", __func__); */
    /* goto done; */
  } // else {
  if (dest_entry.len > 0) {
    skiplist_insert_entry(&addr_list, &dest_entry);
    LOG("[%s] insert dest entry\n", __func__);

#if LOGON
    snode_dump(&dest_entry);
#endif

    mmap((void *)(dest_entry.addr + dest_entry.offset), dest_entry.len,
         PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_FIXED | /* MAP_POPULATE | */
             MAP_ANONYMOUS,
         -1, 0);

    REGISTER_FAULT(dest_entry.addr + dest_entry.offset, dest_entry.len);
  }
  //  }

  if (dest_entry.offset > 0)
    libc_memcpy((void *)dest_entry.addr, (const void *)src_entry->addr,
                dest_entry.offset);

  if (dest_right_fringe_len > 0) {
    libc_memcpy(
        (void *)(dest_entry.addr + dest_entry.offset + dest_entry.len),
        (const void *)(src_entry->addr + dest_entry.offset + dest_entry.len),
        dest_right_fringe_len);
  }

done:
  num_fast_copy++;

  pthread_mutex_unlock(&mu);

  return dest;
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

  pthread_mutex_lock(&mu);

  snode *entry = skiplist_search(&addr_list, (uint64_t)PAGE_ALIGN_DOWN(ptr));
  cannot_optimize = (entry == NULL);

  if (cannot_optimize) {
    // LOG("[%s] entry %p not found\n", __func__, ((uint64_t)ptr) & PAGE_MASK);
    pthread_mutex_unlock(&mu);
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

  uint64_t new_ptr_bounded = (uint64_t)PAGE_ALIGN_DOWN(new_ptr);
  uint64_t left_fringe_len = LEFT_FRINGE_LEN(new_ptr); // actually, 0
  uint64_t right_fringe_len = RIGHT_FRINGE_LEN(new_size, left_fringe_len);

  snode new_entry;
  new_entry.lookup = new_ptr_bounded;
  new_entry.orig = entry->orig;
  new_entry.addr = (uint64_t)new_ptr;
  new_entry.len = new_size - (left_fringe_len + right_fringe_len);
  new_entry.offset = left_fringe_len;

  mmap(new_ptr, new_entry.len, PROT_READ | PROT_WRITE,
       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

  REGISTER_FAULT(new_entry.addr + new_entry.offset, new_entry.len);

  skiplist_insert_entry(&addr_list, &new_entry);

  LOG("[%s] a new entry\n", __func__);
#if LOGON
  snode_dump(&new_entry);
#endif

  // print_trace();

  pthread_mutex_unlock(&mu);

  return new_ptr;
}

// What if a big buffer is sent via multiple sendmsg?

/* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) { */
/*   ensure_init(); */

/*   pthread_mutex_lock(&mu); */

/*   int i; */
/*   for (i = 0; i < msg->msg_iovlen; i++) { */
/*     if (msg->msg_iov[i].iov_len > OPT_THRESHOLD) { */
/*       snode *entry = skiplist_search_buffer_fallin( */
/*           &addr_list, (uint64_t)msg->msg_iov[i].iov_base); */

/*       if (entry) { */
/*         // print(msg->msg_iov[i].iov_base, 0, msg->msg_iov[i].iov_len); */
/*         // snode_dump(entry); */

/*         msg->msg_iov[i].iov_base = */
/*             entry->orig + ((uint64_t)msg->msg_iov[i].iov_base - entry->addr);
 */
/*         // printf("[%d] base: %p, len: %lu\n", i, msg->msg_iov[i].iov_base,
 */
/*         //        msg->msg_iov[i].iov_len); */
/*       } */
/*     } */
/*   } */

/*   pthread_mutex_unlock(&mu); */
/*   return libc_sendmsg(sockfd, msg, flags); */
/* } */

/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) { */
/*   ensure_init(); */

/*   pthread_mutex_lock(&mu); */

/*   int i; */
/*   for (i = 0; i < msg->msg_iovlen; i++) { */
/*     if (msg->msg_iov[i].iov_len > OPT_THRESHOLD) { */
/*       uint64_t left_fringe_len = LEFT_FRINGE_LEN(msg->msg_iov[i].iov_base);
 */
/*       uint64_t right_fringe_len = */
/*           RIGHT_FRINGE_LEN(msg->msg_iov[i].iov_len, left_fringe_len); */
/*       snode new_entry; */
/*       new_entry.lookup = (uint64_t)PAGE_ALIGN_DOWN(msg->msg_iov[i].iov_base);
 */
/*       new_entry.orig = (uint64_t)msg->msg_iov[i].iov_base; */
/*       new_entry.addr = (uint64_t)msg->msg_iov[i].iov_base; */
/*       new_entry.len = */
/*           msg->msg_iov[i].iov_len - (left_fringe_len + right_fringe_len); */
/*       new_entry.offset = left_fringe_len; */

/*       snode *entry = skiplist_search(&addr_list, new_entry.lookup); */

/*       if (entry) { */
/*         // skiplist_delete(&addr_list, entry->lookup); */
/*         entry->orig = new_entry.orig; */
/*         entry->addr = new_entry.addr; */
/*         entry->len = new_entry.len; */
/*         entry->offset = new_entry.offset; */
/*       } else { */
/*         skiplist_insert_entry(&addr_list, &new_entry); */
/*         // skiplist_dump(&addr_list); */
/*       } */
/*     } */
/*   } */

/*   pthread_mutex_unlock(&mu); */
/*   return libc_recvmsg(sockfd, msg, flags); */
/* } */

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
             MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);

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
    mmap(fault_page_start_addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    struct uffdio_range range;
    range.start = (uint64_t)fault_page_start_addr;
    range.len = PAGE_SIZE;

    if (ioctl(uffd, UFFDIO_WAKE, &range) < 0) {
      perror("uffdio wake");
      assert(0);
    }
    goto done;
  }

  LOG("Fault entry\n");
#if LOGON
  snode_dump(fault_buffer_entry);
#endif

  // UNREGISTER_FAULT(fault_buffer_entry->addr + fault_buffer_entry->offset,
  //                  fault_buffer_entry->len);

  const void *src_ptr =
      (void *)(fault_buffer_entry->orig +
               ((uint64_t)fault_page_start_addr - fault_buffer_entry->addr));

  // libc_memcpy(fault_page_start_addr, src_ptr, PAGE_SIZE);

  struct uffdio_copy uffdio_copy;
  uffdio_copy.dst = (long long)fault_page_start_addr;
  uffdio_copy.src = (long long)src_ptr;
  uffdio_copy.len = PAGE_SIZE;
  uffdio_copy.mode = 0;

  if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) {
    perror("userfaultfd copy error");
    abort();
  }

  // UNREGISTER_FAULT(fault_page_start_addr,
  //                  PAGE_SIZE);

  LOG("[%s] copy touched page %p -> %p\n", __func__, src_ptr,
      fault_page_start_addr);

  const char is_first_page =
      (fault_buffer_entry->addr + fault_buffer_entry->offset ==
       (uint64_t)fault_page_start_addr);
  const char is_last_page =
      (fault_buffer_entry->addr + fault_buffer_entry->offset +
           fault_buffer_entry->len ==
       (uint64_t)fault_page_start_addr + PAGE_SIZE);

  if (is_first_page) {
    fault_buffer_entry->offset += PAGE_SIZE;
    fault_buffer_entry->len -= PAGE_SIZE;
  } else if (is_last_page) {
    fault_buffer_entry->len -= PAGE_SIZE;
  } else {
    LOG("[%s] update the entry %p\n", __func__, fault_buffer_entry->lookup);

    snode second_part_entry;
    second_part_entry.lookup = (uint64_t)fault_page_start_addr + PAGE_SIZE;
    second_part_entry.orig = (uint64_t)src_ptr + PAGE_SIZE;
    second_part_entry.addr = (uint64_t)fault_page_start_addr + PAGE_SIZE;
    second_part_entry.len = fault_buffer_entry->addr +
                            fault_buffer_entry->offset +
                            fault_buffer_entry->len - second_part_entry.addr;
    second_part_entry.offset = 0;

    fault_buffer_entry->len -= second_part_entry.len + PAGE_SIZE;

    // TODO: Need to copy data if second_part_entry.len <= OPT_THRESHOLD
    // if (second_part_entry.len > 0) {
    if (second_part_entry.len < PAGE_SIZE) {
      if (second_part_entry.len >= PAGE_SIZE) {
        // mmap(second_part_entry.addr, second_part_entry.len,
        //      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
        //      -1, 0);
        // libc_memcpy(second_part_entry.addr, second_part_entry.orig,
        //             second_part_entry.len);
      }
    } else {
      LOG("[%s] Add new second part to skiplist\n", __func__);
#if LOGON
      snode_dump(&second_part_entry);
#endif

      skiplist_insert_entry(&addr_list, &second_part_entry);

      // REGISTER_FAULT(second_part_entry.addr + second_part_entry.offset,
      //                second_part_entry.len);
    }
  }
  // }

  if (fault_buffer_entry->len >= PAGE_SIZE) {
    LOG("[%s] The first part to skiplist\n", __func__);
#if LOGON
    snode_dump(fault_buffer_entry);
#endif
    // REGISTER_FAULT(fault_buffer_entry->addr + fault_buffer_entry->offset,
    //                fault_buffer_entry->len);
  } else {
    if (fault_buffer_entry->len > 0) {
      libc_memcpy(
          (void *)(fault_buffer_entry->addr + fault_buffer_entry->offset),
          (void *)(fault_buffer_entry->orig + fault_buffer_entry->offset),
          fault_buffer_entry->len);
    }

    LOG("[%s] The entry is deleted\n", __func__);
    skiplist_delete(&addr_list, fault_buffer_entry->lookup);
  }

done : {
  // struct uffdio_range range;
  // range.start = (uint64_t)fault_page_start_addr;
  // range.len = PAGE_SIZE;

  // if (ioctl(uffd, UFFDIO_WAKE, &range) < 0) {
  //   perror("uffdio wake");
  //   assert(0);
  // }

  LOG("[%s] Handled the page %p(%p)\n", __func__, fault_addr,
      fault_page_start_addr);
  num_faults++;
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

  libc_pwrite = bind_symbol("pwrite");
  libc_pwritev = bind_symbol("pwritev");
  libc_memcpy = bind_symbol("memcpy");
  libc_memmove = bind_symbol("memmove");
  libc_realloc = bind_symbol("realloc");
  libc_free = bind_symbol("free");
  libc_send = bind_symbol("send");
  libc_sendmsg = bind_symbol("sendmsg");
  libc_recv = bind_symbol("recv");
  libc_recvmsg = bind_symbol("recvmsg");

  // new tracking code
  skiplist_init(&addr_list);

  pthread_mutex_init(&mu, NULL);

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
      0; // UFFD_FEATURE_PAGEFAULT_FLAG_WP |  UFFD_FEATURE_MISSING_SHMEM |
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
