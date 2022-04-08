-include Makefile.local

PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
INCDIR ?= $(PREFIX)/include

CFLAGS += -std=gnu99 -O3 -g -Wall -I. -Iinclude/ -march=native -fno-omit-frame-pointer -fno-common -mno-avx512f #-Werror
LDFLAGS += -pthread -g

RTE_SDK ?= ${HOME}/dpdk/build
DPDK_PMDS = mlx5
EXTRA_LIBS_DPDK = -libverbs -lmlx5 -lmnl


CFLAGS+= -I$(RTE_SDK)/include -I$(RTE_SDK)/include/dpdk
CFLAGS+= -I$(RTE_SDK)/include/x86_64-linux-gnu/dpdk/
LDFLAGS+= -L$(RTE_SDK)/lib/

LIBS_DPDK= -Wl,--whole-archive -Wl,-rpath=$(abspath $(RTE_SDK)/lib)
LIBS_DPDK+= $(addprefix -lrte_pmd_,$(DPDK_PMDS))
LIBS_DPDK+= -lrte_eal -lrte_mempool -lrte_mempool_ring \
	    -lrte_hash -lrte_ring -lrte_kvargs -lrte_ethdev \
	    -lrte_mbuf -lnuma -lrte_bus_pci -lrte_pci \
	    -lrte_cmdline -lrte_timer -lrte_net \
	    -lrte_bus_vdev -lrte_gso -lrte_kni \
	    -Wl,--no-whole-archive -ldl $(EXTRA_LIBS_DPDK)
	    #-lrte_telemetry\

LDLIBS += -lm -lpthread -lrt -ldl

UTILS_OBJS = $(addprefix lib/utils/,utils.o rng.o timeout.o)
SOCKETS_OBJS = $(addprefix lib/sockets/,control.o transfer.o context.o manage_fd.o \
	epoll.o)
INTERPOSE_OBJS = $(addprefix lib/sockets/,interpose.o)
COPY_INTERPOSE_OBJS = $(addprefix lib/sockets/,copy_interpose.o)
PAGE_FAULT_OBJS = $(addprefix lib/sockets/,page_fault_test.o)
TAS_COPY_INTERPOSE_OBJS = $(addprefix lib/sockets/,tas_copy_interpose.o)
ZIO_INTERPOSE_OBJS = $(addprefix lib/sockets/,zio_interpose.o)
MEM_COUNTER_OBJS = $(addprefix lib/sockets/,mem_counter.o)
CFLAGS += -I. -Isrc/sockets/include

shared_objs = $(patsubst %.o,%.shared.o,$(1))

linux:	copy_interpose.so

all: 	zio_interpose.so \
	tas_copy_interpose.so copy_interpose.so \
	libmem_counter.so page_fault_test.so 

copy_interpose.so: $(call shared_objs, \
	$(COPY_INTERPOSE_OBJS) $(SOCKETS_OBJS) $(UTILS_OBJS))

page_fault_test.so: $(call shared_objs, \
	$(PAGE_FAULT_OBJS) $(SOCKETS_OBJS) $(UTILS_OBJS))

tas_copy_interpose.so: $(call shared_objs, \
	$(TAS_COPY_INTERPOSE_OBJS) $(SOCKETS_OBJS) $(UTILS_OBJS))

zio_interpose.so: $(call shared_objs, \
	$(ZIO_INTERPOSE_OBJS) $(SOCKETS_OBJS) $(UTILS_OBJS))

libmem_counter.so: $(call shared_objs, \
	$(MEM_COUNTER_OBJS) $(SOCKETS_OBJS) $(UTILS_OBJS))

%.shared.o: %.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

%.so:
	$(CC) $(LDFLAGS) -shared $^ $(LOADLIBES) $(LDLIBS) -o $@


clean:
	rm -f *.o src.o \
	  lib\copy_interpose.so lib\tas_copy_interpose.so \
	  lib/page_fault_test.so lib/mem_counter.so 
