#!/bin/bash

#This is the echo server directory
cd ../benchmarks/micro_rpc_cpy

#Go to the client machine and remove any data from previous runs
ssh zio_ae@10.0.0.1 "rm zIO/benchmarks/micro_rpc_cpy/results/thread_sweep/*.dat"

#Perform the Linux experiments first
echo "Linux Runs"


#This is how we run the server. 
#The first command line option is the number of copies. The second is the port.
#After the config file, there is the maximum number of connections and maximum IO size.
./echoserver_linux 5 8000 1 ./echoserver.conf 128 524288 &

#This will ssh to the client machine and run the client benchmark.
#The client command line has the IP, port, number of threads, and then the message size after the config file.
#We want to scale up the number of client threads with the number of server threads.
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 4 ./testclient.conf 524288 >> results/thread_sweep/1thread.dat"

#We want to vary the number of threads with no copies to show there is no interference from zIO.  

./echoserver_linux 0 8000 2 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 8 ./testclient.conf 524288 >> results/thread_sweep/2thread.dat"

./echoserver_linux 0 8000 4 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 16 ./testclient.conf 524288 >> results/thread_sweep/4thread.dat"

./echoserver_linux 0 8000 8 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 32 ./testclient.conf 524288 >> results/thread_sweep/8thread.dat"

#This section will have the zIO experiments.
echo "zIO Runs"

#The server and client configurations are the same, but we use LD_PRELOAD to interpose our code. 
LD_PRELOAD=../../copy_interpose.so ./echoserver_linux 0 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 4 ./testclient.conf 524288 >> results/thread_sweep/1thread_zio.dat"

LD_PRELOAD=../../copy_interpose.so ./echoserver_linux 0 8000 2 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 8 ./testclient.conf 524288 >> results/thread_sweep/2thread_zio.dat"

LD_PRELOAD=../../copy_interpose.so ./echoserver_linux 0 8000 4 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 16 ./testclient.conf 524288 >> results/thread_sweep/4thread_zio.dat"

LD_PRELOAD=../../copy_interpose.so ./echoserver_linux 0 8000 8 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 32 ./testclient.conf 524288 >> results/thread_sweep/8thread_zio.dat"

#After all the different server configurations are done, we run a simple script on the client machine to parse the output, cut the warmup period and get the average of the run. 

echo "Processing..."
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy/results/thread_sweep; ./process.sh"

#The processing script summarizes the results in a final.dat file, which we can retrieve. 
scp 10.0.0.1:~/zIO/benchmarks/micro_rpc_cpy/results/thread_sweep/final.dat .
cat final.dat
rm final.dat
