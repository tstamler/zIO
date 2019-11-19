#! /bin/bash

rm -rf ./pmem/*
drop_caches
LD_PRELOAD=/home/tstamler/tas/lib/libtas_interpose.so ./redis-server ../redis_ext4.conf
