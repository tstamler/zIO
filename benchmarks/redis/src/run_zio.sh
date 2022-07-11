#! /bin/bash

rm -rf ../pmem/*
LD_PRELOAD=/home/zio_ae/zIO/tas/lib/redis_interpose.so ./redis-server ../redis_ext4.conf 2>error.log
