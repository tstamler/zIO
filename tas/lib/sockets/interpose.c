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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#define __USE_GNU
#include <dlfcn.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/userfaultfd.h>
#include <assert.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>

#include <utils.h>
#include <tas_sockets.h>
#include <skiplist.h>

#define OPT_THRESHOLD 0xfffffffffffffffff
//#define OPT_THRESHOLD 8191

#define PAGE_MASK 0xfffffffff000

#define MAX_UFFD_MSGS 1

#define UFFD_PROTO

//#define LOG(...) fprintf(stderr, __VA_ARGS__)
#define LOG(str, ...) while(0) {}

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

uint64_t num_fast_writes, num_slow_writes, num_fast_copy, num_slow_copy, num_faults;

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
    struct sockaddr *src_addr, socklen_t *addrlen) = NULL;
static ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg, int flags)
    = NULL;
static ssize_t (*libc_readv)(int sockfd, const struct iovec *iov, int iovcnt)
    = NULL;
static ssize_t (*libc_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags)
    = NULL;
static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len,
    int flags, const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags)
    = NULL;
static ssize_t (*libc_writev)(int sockfd, const struct iovec *iov, int iovcnt)
    = NULL;
static int (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout) = NULL;
static int (*libc_pselect)(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)
    = NULL;

static void* (*libc_memcpy)(void* dest, const void* src, size_t n);
static void* (*libc_memmove)(void* dest, const void* src, size_t n);

skiplist addr_list;

void print_trace(void) {
    char **strings;
    size_t i, size;
    enum Constexpr { MAX_SIZE = 1024 };
    void *array[MAX_SIZE];
    size = backtrace(array, MAX_SIZE);
    strings = backtrace_symbols(array, size);
    for (i = 0; i < size; i++)
        LOG("%s\n", strings[i]);
    free(strings);
}


int socket(int domain, int type, int protocol)
{
  ensure_init();

  /* if not a TCP socket, pass call to libc */
  if (domain != AF_INET || type != SOCK_STREAM) {
    fprintf(stderr, "TAS: calling libc socket\n");
    return libc_socket(domain, type, protocol);
  }

  return tas_socket(domain, type, protocol);
}

int close(int sockfd)
{
  int ret;
  ensure_init();
  if ((ret = tas_close(sockfd)) == -1 && errno == EBADF) {
    return libc_close(sockfd);
  }
  return ret;
}

int shutdown(int sockfd, int how)
{
  int ret;
  ensure_init();
  if ((ret = tas_shutdown(sockfd, how)) == -1 && errno == EBADF) {
    return libc_shutdown(sockfd, how);
  }
  return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_bind(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_bind(sockfd, addr, addrlen);
  }
  return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_connect(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_connect(sockfd, addr, addrlen);
  }
  return ret;
}

int listen(int sockfd, int backlog)
{
  int ret;
  ensure_init();
  if ((ret = tas_listen(sockfd, backlog)) == -1 && errno == EBADF) {
    fprintf(stderr, "TAS: calling libc listen\n");
    return libc_listen(sockfd, backlog);
  }
  return ret;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int flags)
{
  int ret;
  ensure_init();
  if ((ret = tas_accept4(sockfd, addr, addrlen, flags)) == -1 &&
      errno == EBADF)
  {
    return libc_accept4(sockfd, addr, addrlen, flags);
  }
  return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_accept(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_accept(sockfd, addr, addrlen);
  }
  return ret;
}

int fcntl(int sockfd, int cmd, ...)
{
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
    socklen_t *optlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_getsockopt(sockfd, level, optname, optval, optlen)) == -1 &&
      errno == EBADF)
  {
    return libc_getsockopt(sockfd, level, optname, optval, optlen);
  }
  return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
    socklen_t optlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_setsockopt(sockfd, level, optname, optval, optlen)) == -1 &&
      errno == EBADF)
  {
    return libc_setsockopt(sockfd, level, optname, optval, optlen);
  }
  return ret;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_getsockname(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_getsockname(sockfd, addr, addrlen);
  }
  return ret;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int ret;
  ensure_init();
  if ((ret = tas_getpeername(sockfd, addr, addrlen)) == -1 && errno == EBADF) {
    return libc_getpeername(sockfd, addr, addrlen);
  }
  return ret;
}

ssize_t read(int sockfd, void *buf, size_t count)
{
  ssize_t ret;
  static void* prev_addr, *prev_orig; //, *max_addr;
  static size_t prev_len;
  uint64_t original;
  ensure_init();
  if ((ret = tas_read(sockfd, buf, count, &original)) == -1 && errno == EBADF) {
    return libc_read(sockfd, buf, count);
  }
  LOG("tas read %zu bytes, page mask %lx\n", ret, ((uint64_t) buf) & PAGE_MASK);
  if(ret > OPT_THRESHOLD){
	 
	 //if((uint64_t) original > (uint64_t) max_addr) max_addr = original;

	 //uint64_t original = tas_get_buf_addr(sockfd, buf); 
	 LOG( "reading from network at %p, size %zu, key %lx, original %p\n", buf, ret, ((uint64_t) buf) & PAGE_MASK, original);
	 //LOG("returned addr %p, highest so far %p\n", original, max_addr);	 
	 LOG("old roll_addr %p, prev_addr %p, prev_len %zu\n", roll_addr[sockfd].last_addr, prev_addr, prev_len);
	 if((((uint64_t) prev_addr + prev_len) & PAGE_MASK) == (((uint64_t) buf) & PAGE_MASK) && prev_len < OPT_THRESHOLD){
		//roll_addr[sockfd].last_addr = (uint64_t) prev_addr + prev_len;
		roll_addr[sockfd].last_addr = (uint64_t) buf + ret;
		roll_addr[sockfd].size = prev_len + ret;
		roll_addr[sockfd].original = prev_orig;
		LOG("small addr found\n");
	 } else {

		 if(roll_addr[sockfd].last_addr == (uint64_t) buf) {
		     roll_addr[sockfd].last_addr = (uint64_t) buf + ret;
		     roll_addr[sockfd].size += ret;
		     LOG("rolling, old original %p new original %p\n", roll_addr[sockfd].original, original);
		 } else {
		     roll_addr[sockfd].last_addr = (uint64_t) buf + ret;
		     roll_addr[sockfd].size = ret;
		     roll_addr[sockfd].original = original;
		     LOG("not rolling\n");
		 }
	         LOG("small addr not found: prev %p, current %p\n", (uint64_t) prev_addr + prev_len, (uint64_t) buf);
	 }

	 uint64_t old_addr = (roll_addr[sockfd].last_addr - roll_addr[sockfd].size) & PAGE_MASK;
	 LOG("new roll_addr %p, size %zu, original %p inserting at %p\n", roll_addr[sockfd].last_addr, roll_addr[sockfd].size, original, old_addr);
	 skiplist_insert(&addr_list, old_addr, roll_addr[sockfd].original, roll_addr[sockfd].size, 0); 
  }
  prev_addr = buf;
  prev_len = ret;
  prev_orig = original; 
  return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_recv(sockfd, buf, len, flags)) == -1 && errno == EBADF) {
    return libc_recv(sockfd, buf, len, flags);
  }
  return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
    struct sockaddr *src_addr, socklen_t *addrlen)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_recvfrom(sockfd, buf, len, flags, src_addr, addrlen)) == -1 &&
      errno == EBADF)
  {
    return libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  }
  return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_recvmsg(sockfd, msg, flags)) == -1 && errno == EBADF) {
    return libc_recvmsg(sockfd, msg, flags);
  }
  return ret;
}

ssize_t readv(int sockfd, const struct iovec *iov, int iovcnt)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_readv(sockfd, iov, iovcnt)) == -1 && errno == EBADF) {
    return libc_readv(sockfd, iov, iovcnt);
  }
  return ret;
}

ssize_t write(int sockfd, const void *buf, size_t count)
{
  ssize_t ret, ret2;
  ensure_init();
  if ((ret = tas_write(sockfd, buf, count)) == -1 && errno == EBADF) {
    size_t new_len = count;
    ret = 0;
    if (count > OPT_THRESHOLD) {
	snode* entry = skiplist_search(&addr_list, ((uint64_t) buf) & PAGE_MASK);
	LOG("writing to linux from %p, bounded %p, size %zu, entry %p\n", buf, ((uint64_t) buf) & PAGE_MASK, count, entry);
	if(entry && entry->len <= count) {
	    new_len = count - entry->len;

	    //clean up old skiplist entry
	
	    uint64_t src_bounded = ((uint64_t) buf) & PAGE_MASK;
	    uint32_t register_len = (count & PAGE_MASK) - 4096;
#if 0	    
	    uint64_t mmap_ret = mmap((void*) (src_bounded + 4096), (count & PAGE_MASK) - 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	    if(mmap_ret != (src_bounded + 4096)){
	    //if(munmap((void*) (dest_bounded + 4096), register_len) < 0){
	    //if(mprotect((void*) (dest_bounded + 4096), register_len, PROT_NONE) < 0){
	    	LOG("write bad mmap return %p... parameters %p, %zu\n", mmap_ret, src_bounded + 4096, (count & PAGE_MASK) - 4096);
		perror("memcpy mmap");
		abort();
	    }
#else
	    struct uffdio_range uffdio_unregister;
	    uffdio_unregister.start = src_bounded + 4096;
	    uffdio_unregister.len = register_len;
		
	    LOG("uffd unregistering addr %p-%p, len %zu\n", src_bounded + 4096, src_bounded + 4096 + register_len, register_len);
	    if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) {
		perror("ioctl uffdio_unregister");
		abort();
	    }
#endif
	    LOG("preparing encoding of size %zu, new_len = %zu, count = %zu, entry->len=%zu\n", sizeof(struct addr_encoding), new_len, count, entry->len);
	    struct addr_encoding* code = ((void*) buf) + new_len;
	    code->addr = entry->orig;
	    code->len = entry->len;
	    code->code = 0xdeadbeef;
	    new_len = sizeof(struct addr_encoding);
	    //new_len += sizeof(struct addr_encoding);
	    ret = count;
	    LOG("encoding ready\n");
	    num_fast_writes++;
	}
	else {
		LOG("entry %p not found\n", buf);
		//printf("entry not found\n");
	}
	skiplist_delete(&addr_list, ((uint64_t) buf) & PAGE_MASK);
    	LOG("write len %zu\n", new_len);
    }
    //LOG("write len %zu\n", new_len);
    //new_len = sizeof(struct addr_encoding);
    //ret = count;
    
    if(new_len > OPT_THRESHOLD) num_slow_writes++;

    ret2 = libc_write(sockfd, buf, new_len);
    
    if(ret2 < 0 || ret == 0) return ret2;
    else return ret;
    //return libc_write(sockfd, buf, new_len);
  }
  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_send(sockfd, buf, len, flags)) == -1 && errno == EBADF) {
    return libc_send(sockfd, buf, len, flags);
  }
  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_sendto(sockfd, buf, len, flags, dest_addr, addrlen)) == -1 &&
      errno == EBADF)
  {
    return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  }
  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_sendmsg(sockfd, msg, flags)) == -1 && errno == EBADF) {
    return libc_sendmsg(sockfd, msg, flags);
  }
  return ret;
}

ssize_t writev(int sockfd, const struct iovec *iov, int iovcnt)
{
  ssize_t ret;
  ensure_init();
  if ((ret = tas_writev(sockfd, iov, iovcnt)) == -1 && errno == EBADF) {
    return libc_writev(sockfd, iov, iovcnt);
  }
  return ret;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)
{
  return libc_select(nfds, readfds, writefds, exceptfds, timeout);
  //return tas_select(nfds, readfds, writefds, exceptfds, timeout);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    const struct timespec *timeout, const sigset_t *sigmask)
{
  return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
  //return tas_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int epoll_create(int size)
{
  return tas_epoll_create(size);
}

int epoll_create1(int flags)
{
  return tas_epoll_create1(flags);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
  return tas_epoll_ctl(epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
    int timeout)
{
  return tas_epoll_wait(epfd, events, maxevents, timeout);
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
    int timeout, const sigset_t *sigmask)
{
  return tas_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

void* memcpy (void* dest, const void* src, size_t n){
  
  ensure_init();	

  static uint64_t prev_start, prev_end; 
  //TODO: parse big copy for multiple small copies 
  
  if(n > OPT_THRESHOLD){
	LOG("copying %p-%p to %p-%p, size %zu\n", src, src + n, dest, dest+n, n);
  	//skiplist_dump(&addr_list);
	snode* entry = skiplist_search(&addr_list, ((uint64_t) src) & PAGE_MASK);
	//fprintf(stderr, "searching for %lx ret %p\n", ((uint64_t) src) & PAGE_MASK, entry);
	//if(n > 16000){
	//       	print_trace();
	//}
	if(entry) {
		uint64_t original = entry->orig;
		uint32_t length = entry->len;
		uint64_t old_offset = entry->offset;

		uint64_t dest_bounded = ((uint64_t) dest) & PAGE_MASK;
		uint64_t src_bounded = ((uint64_t) src) & PAGE_MASK;
		uint64_t offset = ((uint64_t) dest) - dest_bounded;
		uint64_t register_len = (n - 4096) & PAGE_MASK;

		if((uint64_t) dest > prev_start && (uint64_t) dest < prev_end) goto done;
//#ifndef UFFD_PROTO		
	
		/*static int trace_next = 0;	
  		if(trace_next == 1){
			print_trace();
			trace_next = 0;
		}
		if(n > 16000){
		       	print_trace();
			trace_next = 0;
		}*/
		
		//clean up old skiplist entry
		uint64_t ret;
#if 0	
		ret = mmap((void*) (src_bounded + 4096), register_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	        if(ret != (src_bounded + 4096)){
		//if(munmap((void*) (dest_bounded + 4096), register_len) < 0){
		//if(mprotect((void*) (dest_bounded + 4096), register_len, PROT_NONE) < 0){
			fprintf(stderr, "first bad mmap return %p... parameters %p, %zu\n", ret, src_bounded + 4096, register_len);
			perror("memcpy mmap");
			abort();
		}
#else
		struct uffdio_range uffdio_unregister;
		uffdio_unregister.start = src_bounded + 4096;
		uffdio_unregister.len = register_len;
		
		LOG("uffd unregistering addr %p-%p, len %zu\n", src_bounded + 4096, src_bounded + 4096 + register_len, register_len);
	    	if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_unregister) == -1) {
			perror("ioctl uffdio_unregister");
			abort();
		}
#endif	
		skiplist_delete(&addr_list, ((uint64_t) src) & PAGE_MASK);
		//fprintf(stderr, "deleting %lx ret %d\n", ((uint64_t) src) & PAGE_MASK, ret);
//#endif	
		//if(length < n) register_len = (length - 4096) & PAGE_MASK;
//#if 0
#ifdef UFFD_PROTO

		//the offset ends up corresponding to the amount of data at the END of the buffer
		//thus, this might *seem* backward
		if(offset >= old_offset){
			LOG("complete buffer: old offset %zu, new offset %zu\n", old_offset, offset);
			LOG("copying before buffer: %zu bytes from %p-%p to %p-%p\n", 4096-offset, src, src+(4096-offset), dest, dest+(4096-offset));
			libc_memcpy(dest, src, 4096-offset);
		} else {
			uint32_t first_copy = 4096 - old_offset;
			LOG("incomplete buffer: old offset %zu, new offset %zu\n", old_offset, offset);
			LOG("copying before buffer (1): %zu bytes from %p-%p to %p-%p\n", first_copy, src, src+(4096-old_offset), dest, dest+first_copy);
			libc_memcpy(dest, src, first_copy);
			uint32_t second_copy = (4096 - offset) - first_copy;
			LOG("copying before buffer (2): %zu bytes from %p-%p to %p-%p\n", second_copy, original+first_copy, original+first_copy+second_copy, dest + first_copy, dest+first_copy+ second_copy);
			libc_memcpy(dest + first_copy, original + first_copy, second_copy);
		}
		
		//hack around
		if(n < register_len * 2){
			LOG("copying after buffer: %zu bytes from %p-%p to %p-%p\n", offset, original + (n-offset), original + n, dest + (n-offset), dest + n);
			libc_memcpy(dest + (n - offset), original + (n - offset), offset); 
		}
		//make based on n and not offset?


		LOG("mmaping for uffd at %p, length %zu\n", dest_bounded + 4096, register_len);
		ret = mmap(((void*)(dest_bounded + 4096)), register_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	        if(ret != (dest_bounded + 4096)){
		//if(munmap((void*) (dest_bounded + 4096), register_len) < 0){
		//if(mprotect((void*) (dest_bounded + 4096), register_len, PROT_NONE) < 0){
			fprintf(stderr, "bad mmap return %p... parameters %p, %zu\n", ret, dest_bounded + 4096, register_len);
			perror("memcpy mmap");
			abort();
		}

		struct uffdio_register uffdio_register;
		uffdio_register.range.start = dest_bounded + 4096;
		uffdio_register.range.len = register_len;
		uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	        uffdio_register.ioctls = 0;
		
		LOG("uffd registering addr %p-%p, len %zu\n", dest_bounded + 4096, dest_bounded + 4096 + register_len, register_len);
	    	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
			perror("ioctl uffdio_register");
			abort();
		}
		LOG("successfully mapped and registered %p\n", dest_bounded + 4096);
		//memcpy((dest_bounded+4096), src, 32);

		LOG("inserting original %p at location %p\n", original, dest_bounded);
		//skiplist_insert(&addr_list, dest_bounded, original, length, offset);
		skiplist_insert(&addr_list, dest_bounded, original, n, offset);
		//fprintf(stderr, "inserting %lx ret %d\n", ((uint64_t) dest) & PAGE_MASK, ret);
		//skiplist_dump(&addr_list);
done:
		prev_start = dest;
		prev_end = dest + n;
		num_fast_copy++;

		return dest;
#else
//#endif
		skiplist_insert(&addr_list, dest_bounded, original, length, offset);
		//fprintf(stderr, "inserting %lx ret %d\n", ((uint64_t) dest) & PAGE_MASK, ret);
		//skiplist_dump(&addr_list);
#endif
		
#ifdef NO_COPY_TEST  		
		return libc_memcpy(dest, src, 32);
#endif
	}else{
		LOG("appropriate size copy, but can't find %p in skiplist\n", ((uint64_t) src) & PAGE_MASK);
		num_slow_copy++;
	}
  }else if(n > 1024) LOG("sizeable, but not large enough copy from %p to %p of size %zu\n", dest, src, n);
  return libc_memcpy(dest, src, n);
}

void* memmove (void* dest, const void* src, size_t n){
  
  ensure_init();
  if(n > OPT_THRESHOLD){
	LOG("moving %p to %p, size %zu\n", src, dest, n);
  	//return dest;
  }else if(n > 1024) LOG("sizeable, but not large enough move from %p to %p of size %zu\n", dest, src, n);
  return libc_memmove(dest, src, n);
}


/******************************************************************************/
/* Helper functions */

static void *bind_symbol(const char *sym)
{
  void *ptr;
  if ((ptr = dlsym(RTLD_NEXT, sym)) == NULL) {
    fprintf(stderr, "flextcp socket interpose: dlsym failed (%s)\n", sym);
    abort();
  }
  return ptr;
}

void handle_missing_fault(uint64_t page_boundary, uint32_t fault_flags)
{
	snode* entry;
        int i = 0;
	uint64_t base_addr;
	char* test_buf[1024*1024];

	LOG("handling fault at %p\n", page_boundary);
	for(i = 1; i<50; i++){
		base_addr = page_boundary - i*4096;
		LOG("searching for %p\n", base_addr);
		entry = skiplist_search(&addr_list, base_addr);
		if(entry) break;
	}

	if(entry == NULL){
	  LOG("page fault can't find skiplist entry, aborting\n");
	  abort();
	}
	LOG("found %p entry at %p, lookup %p, size %lu, offset %p\n", entry, base_addr, entry->lookup, entry->len, entry->offset);
	
	uint64_t original = entry->orig;
	uint32_t length = entry->len;
	uint64_t offset = entry->offset;
	void* newptr;

	LOG("mapping page fault at %p with %zu bytes\n", base_addr + 4096, (length & PAGE_MASK) - 4096);
	newptr = mmap((void*) (base_addr + 4096), (length & PAGE_MASK) - 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	//newptr = mmap((void*)(base_addr + 4096), length - 4096, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS, 0, 0);
    	if (newptr < 0) {
	    perror("newptr mmap");
	    assert(0);
	}
      
        if (((uint64_t) newptr) != (base_addr + 4096)) {
	    fprintf(stderr, "page fault mmap: newptr != base_addr... %p != %p\n", newptr, base_addr + 4096);
	}
	LOG("copying into page fault at %p from %p with %zu\n", base_addr + 4096, ((void *) original) + (4096 - offset), (length & PAGE_MASK) - 4096);

	LOG("testing base from %p to %p\n", base_addr+4096, base_addr+length);
	/*for(i = 4096; i < length; i+=4096) {
		LOG("copying %zu\n", i);
		libc_memcpy((void*) base_addr+i, test_buf+i, 4096);
	}
		//libc_memcpy((void*) (base_addr + 4096), test_buf, (length & PAGE_MASK) - 4096);
	LOG("testing original\n");	
	for(i = 4096 - offset; i < length; i+=4096) {
		LOG("copying %zu\n", i);
		libc_memcpy(test_buf+i, (void*) original+i, 4096);
	}
	libc_memcpy(test_buf, (void*) (original + (4096 - offset)), (length & PAGE_MASK) - 4096);
	
	libc_memcpy((void*) (base_addr + 4096), (void*) (original + (4096 - offset)), (length & PAGE_MASK) - 4096);
	assert(page_boundary);*/

	skiplist_delete(&addr_list, base_addr);
	num_faults++;
}

void *print_stats(){

	while(1){
		LOG_STATS("fast copies: %lu\tslow copies: %lu\tfast writes: %lu\tslow writes: %lu\tpage faults: %lu\n", num_fast_copy, num_slow_copy, num_fast_writes, num_slow_writes, num_faults);
  		num_fast_writes = num_slow_writes = num_fast_copy = num_slow_copy = num_faults = 0;
		sleep(1);	
	}
}

void *handle_fault()
{
  static struct uffd_msg msg[MAX_UFFD_MSGS];
  ssize_t nread;
  uint64_t fault_addr;
  uint64_t fault_flags;
  uint64_t page_boundry;
  struct uffdio_range range;
  int ret;
  int nmsgs;
  int i;

  //cpu_set_t cpuset;
  //pthread_t thread;
  //thread = pthread_self();
				  
  //CPU_ZERO(&cpuset);
				    
  //CPU_SET(FAULT_THREAD_CPU, &cpuset);
				      
  //int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
				        
  //if (s != 0) {
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

			page_boundry = fault_addr & ~(4096 - 1);

			LOG("handling fault at %p, calling function %p\n", fault_addr, &handle_missing_fault);
			handle_missing_fault(page_boundry, fault_flags);

		        range.start = (uint64_t)page_boundry;
		        range.len = 4096;

		        ret = ioctl(uffd, UFFDIO_WAKE, &range);

		        if (ret < 0) {
		 	    perror("uffdio wake");
		            assert(0);
			}
		}			     
		else if (msg[i].event & UFFD_EVENT_UNMAP){
		        fprintf(stderr, "Received an unmap event\n");
		        assert(0);
		}
		else if (msg[i].event & UFFD_EVENT_REMOVE) {
		        fprintf(stderr, "received a remove event\n");
		        assert(0);
		}
		else {
		        fprintf(stderr, "received a non page fault event\n");
		        assert(0);
		}
	  }
     }
}

static void init(void)
{
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
  libc_send = bind_symbol("send");
  libc_sendto = bind_symbol("sendto");
  libc_sendmsg = bind_symbol("sendmsg");
  libc_writev = bind_symbol("writev");
  libc_select = bind_symbol("select");
  libc_pselect = bind_symbol("pselect");
  
  libc_memmove = bind_symbol("memmove");
  libc_memcpy = bind_symbol("memcpy");

  //new tracking code
  skiplist_init(&addr_list);

#ifdef UFFD_PROTO
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
      perror("uffd");
      abort();
  }

  num_fast_writes = num_slow_writes = num_fast_copy = num_slow_copy = num_faults = 0;

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0; //UFFD_FEATURE_PAGEFAULT_FLAG_WP |  UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_MISSING_HUGETLBFS;// | UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_EVENT_REMOVE;
  uffdio_api.ioctls = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
      perror("ioctl uffdio_api");
      abort();
  }

  if (pthread_create(&fault_thread, NULL, handle_fault, 0) != 0){
      perror("fault thread create");
      abort();
  }

  if (pthread_create(&stats_thread, NULL, print_stats, 0) != 0){
      perror("stats thread create");
      abort();
  }

  LOG("uffd initialized\n");
#endif

  if (tas_init() != 0) {
    abort();
  }
}


static inline void ensure_init(void)
{
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
