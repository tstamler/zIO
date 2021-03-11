#! /bin/bash

rm -rf /home/tstamler/stratas/strata/bench/redis-3.2.8/pmem/*
LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/libtas_interpose.so ./redis-server ../redis_ext4.conf
