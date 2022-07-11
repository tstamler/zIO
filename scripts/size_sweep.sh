#!/bin/bash

#Number of threads to run for each client machine
CLIENT_THREADS=6

#This is the echo server directory
cd ../benchmarks/micro_rpc_cpy

#Go to the client machine and remove any data from previous runs
ssh zio_ae@10.0.0.1 "rm zIO/benchmarks/micro_rpc_cpy/results/size_sweep/*.dat"

#Perform the Linux experiments first
echo "Linux Runs"


#This is how we run the server. 
#The first command line option is the number of copies. The second is the port.
#After the config file, there is the maximum number of connections and maximum IO size.
./echoserver_linux 5 8000 1 ./echoserver.conf 128 8192 &

#This will ssh to the client machine and run the client benchmark.
#The client command line has the IP, port, number of threads, and then the message size after the config file. 
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 8192 >> results/size_sweep/8KB.dat"

#We want to run 5 copies with a varying message size. 

./echoserver_linux 5 8000 1 ./echoserver.conf 128 16384 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 16384 >> results/size_sweep/16KB.dat"

./echoserver_linux 5 8000 1 ./echoserver.conf 128 32768 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 32768 >> results/size_sweep/32KB.dat"

./echoserver_linux 5 8000 1 ./echoserver.conf 128 65536 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 65536 >> results/size_sweep/64KB.dat"

./echoserver_linux 5 8000 1 ./echoserver.conf 128 131072 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 131072 >> results/size_sweep/128KB.dat"

./echoserver_linux 5 8000 1 ./echoserver.conf 128 262144 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 262144 >> results/size_sweep/256KB.dat"

#This section will have the zIO experiments.
echo "zIO Runs"

#The server and client configurations are the same, but we use LD_PRELOAD to interpose our code. 
LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 8192 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 8192 >> results/size_sweep/8KB_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 16384 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 16384 >> results/size_sweep/16KB_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 32768 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 32768 >> results/size_sweep/32KB_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 65536 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 65536 >> results/size_sweep/64KB_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 131072 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 131072 >> results/size_sweep/128KB_zio.dat"

LD_PRELOAD=../../tas/lib/copy_interpose.so ./echoserver_linux 5 8000 1 ./echoserver.conf 128 262144 &

ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy; timeout 30 ./testclient_linux 10.0.0.6 8000 $CLIENT_THREADS ./testclient.conf 262144 >> results/size_sweep/256KB_zio.dat"

#After all the different server configurations are done, we run a simple script on the client machine to parse the output, cut the warmup period and get the average of the run. 

echo "Processing..."
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/micro_rpc_cpy/results/size_sweep; ./process.sh"

#The processing script summarizes the results in a final.dat file, which we can retrieve. 
scp 10.0.0.1:~/zIO/benchmarks/micro_rpc_cpy/results/size_sweep/final.dat .
cat final.dat
rm final.dat
