TARGETS = echoserver_linux testclient_linux echoserver_ll \
	  echoserver_mtcp testclient_mtcp

TAS_CODE?=${HOME}/stratas_dev/tas

CFLAGS = -std=gnu99 -g -Wall -O3 -march=native \
	-I$(TAS_CODE)/include -I$(TAS_CODE)/lib/tas/include
LDFLAGS =-m64 -g -O3 -pthread  -march=native -no-pie
LDLIBS = -lrt

ESOBJS_COMMON= $(TAS_CODE)/lib/utils/rng.o \
	icache_fill1.o icache_fill8.o icache_fill64.o icache_fill256.o \
	icache_fill512.o

include ../common/Makefile.mtcp


all: echoserver_linux testclient_linux echoserver_ll
all-sockets: echoserver_linux testclient_linux
all-mtcp: echoserver_mtcp testclient_mtcp
all-ll: echoserver_ll


echoserver_linux: echoserver.o $(ESOBJS_COMMON)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

echoserver_ll: echoserver_ll.o $(ESOBJS_COMMON) \
		$(TAS_CODE)/lib/libtas.so
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

echoserver_mtcp: echoserver.mtcp.o $(ESOBJS_COMMON)
	$(CC) $(LDFLAGS) $(MTCP_LDFLAGS) -o $@ $^ $(LDLIBS) $(MTCP_LDLIBS)

testclient_linux: testclient.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

testclient_mtcp: testclient.mtcp.o
	$(CC) $(LDFLAGS) $(MTCP_LDFLAGS) -o $@ $^ $(LDLIBS) $(MTCP_LDLIBS)


icache_fill1.S: icache_loadgen.py
	python icache_loadgen.py 32768 1 icache_fill1 >$@

icache_fill8.S: icache_loadgen.py
	python icache_loadgen.py 4096 8 icache_fill8 >$@

icache_fill64.S: icache_loadgen.py
	python icache_loadgen.py 512 64 icache_fill64 >$@

icache_fill256.S: icache_loadgen.py
	python icache_loadgen.py 128 256 icache_fill256 >$@

icache_fill512.S: icache_loadgen.py
	python icache_loadgen.py 64 512 icache_fill512 >$@


%.mtcp.o: %.c
	$(CC) $(CFLAGS) $(MTCP_CFLAGS) -c -o $@ $<


clean:
	rm -f *.o icache_fill*.S ${TARGETS}

.PHONY: all all-sockets all-mtcp clean
