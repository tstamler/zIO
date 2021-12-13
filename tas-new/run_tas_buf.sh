#!/bin/sh

echo $1

sudo ./tas/tas --ip-addr=10.0.0.12 --fp-cores-max=4 --cc=const-rate --cc-const-rate=100000000000 --fp-no-ints --fp-no-autoscale --tcp-rxbuf-len=$1 --tcp-txbuf-len=$1 --dpdk-extra="-w 0000:d8:00.1" --tcp-link-bw=40
