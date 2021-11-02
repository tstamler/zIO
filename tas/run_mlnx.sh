#!/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/tstamler/dpdk/build/lib
./tas/tas --ip-addr=10.0.0.4 --fp-cores-max=4 --fp-no-ints --fp-no-autoscale --dpdk-extra="-w 0000:d8:00.0"
