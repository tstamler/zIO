#!/bin/bash

CLIENT_THREADS=4

#This is the echo server directory
cd ../benchmarks/micro_rpc_cpy

#Go to the client machine and remove any data from previous runs
ssh zio_ae@10.0.0.1 "rm zIO/benchmarks/micro_rpc_cpy/results/copy_sweep/*.dat"

#Perform the Linux experiments first
echo "Linux Runs"


#This is how we run the server. 
#The first command line option is the number of copies. The second is the port.
#After the config file, there is the maximum number of connections and maximum IO size.
./echoserver_linux 0 8000 1 ./echoserver.conf 128 524288 &

#This will ssh to the client machine and run the client benchmark.
#The client command line has the IP, port, number of threads, and then the message size after the config file. 
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/0copy.dat"

#We want to run 512KB messages with a varying number of copies on the server side. 

./echoserver_linux 1 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/1copy.dat"

./echoserver_linux 2 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/2copy.dat"

./echoserver_linux 4 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/4copy.dat"

./echoserver_linux 8 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/8copy.dat"

./echoserver_linux 12 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/12copy.dat"

#This section will have the zIO experiments.
echo "zIO Runs"

#The server and client configurations are the same, but we use LD_PRELOAD to interpose our code. 
LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 0 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/0copy_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 1 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/1copy_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 2 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/2copy_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 4 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/4copy_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 8 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/8copy_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 12 8000 1 ./echoserver.conf 128 524288 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 524288 >> results/copy_sweep/12copy_zio.dat"

#After all the different server configurations are done, we run a simple script on the client machine to parse the output, cut the warmup period and get the average of the run. 

echo "Processing..."
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy/results/copy_sweep; ./process.sh"

#The processing script summarizes the results in a final.dat file, which we can retrieve. 
scp 10.0.0.1:~/zIO/benchmarks/micro_rpc_cpy/results/copy_sweep/final.dat .
cat final.dat
rm final.dat
