#! /bin/bash

rm -rf /home/tstamler/stratas/strata/bench/redis-3.2.8/pmem/*
#LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/libtas_interpose.so valgrind --ignore-ranges=0x0-0x1000000 ./redis-server ../redis_ext4.conf
LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/libtas_interpose.so valgrind --show-mismatched-frees=no --expensive-definedness-checks=no --undef-value-errors=no --show-leak-kinds=none -q --vgdb=no ./redis-server ../redis_ext4.conf
