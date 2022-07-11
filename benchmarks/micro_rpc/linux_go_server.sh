#!/bin/bash 

#./echoserver_linux $1 9999 $2 ./echoserver.conf $3 $4
#LD_PRELOAD=./copy_interpose.so ./echoserver_linux $1 9999 $2 ./echoserver.conf $3 $4
LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/page_fault_test.so ./echoserver_linux $1 9999 $2 ./echoserver.conf $3 $4
