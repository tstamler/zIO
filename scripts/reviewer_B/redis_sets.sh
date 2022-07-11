#!/bin/bash

cd ../benchmarks/redis/src/

#In this test, we demonstrate how zIO runs with Redis and accelerates SET requests.


#We clear out any existing data before running the tests. 
ssh zio_ae@10.0.0.1 "rm zIO/benchmarks/redis/results/*.dat"

echo "Linux Runs"

#We want to delete any existing Redis files in the pmem filesystem
rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
#This script does the necessary setup and runs the redis server. Redis is configured to persist writes after each batch of SET requests. 
./run_redis_other.sh &

#Here we ssh into the client machine and run the redis-benchmark client. The parameters are the IP, port, value size, type of request, client threads, output type, and then number of requests to run. 

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((8*1024)) -t set --threads 8 --csv -n 2560000 >> /home/zio_ae/zIO/benchmarks/redis/results/8KB.dat"
sleep 60

#We want to kill and restart the server after each test so we don't run out of space. 
pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 16384 -t set --threads 8 --csv -n 640000 >> /home/zio_ae/zIO/benchmarks/redis/results/16KB.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((32*1024)) -t set --threads 8 --csv -n 160000 >> /home/zio_ae/zIO/benchmarks/redis/results/32KB.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 65536 -t set --threads 8 --csv -n 160000 >> /home/zio_ae/zIO/benchmarks/redis/results/64KB.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 131072 -t set --threads 8 --csv -n 40000 >> /home/zio_ae/zIO/benchmarks/redis/results/128KB.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((256*1024)) -t set --threads 8 --csv -n 40000 >> /home/zio_ae/zIO/benchmarks/redis/results/256KB.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 524288 -t set --threads 8 --csv -n 10000 >> /home/zio_ae/zIO/benchmarks/redis/results/512KB.dat"
sleep 60

pkill redis-server
sleep 5

#Here we run the zIO tests, only the running script is modified to run zIO instead. 
echo "zIO Runs"

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_zio.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((8*1024)) -t set --threads 8 --csv -n 2560000 >> /home/zio_ae/zIO/benchmarks/redis/results/8KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_zio.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 16384 -t set --threads 8 --csv -n 640000 >> /home/zio_ae/zIO/benchmarks/redis/results/16KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_zio.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((32*1024)) -t set --threads 8 --csv -n 640000 >> /home/zio_ae/zIO/benchmarks/redis/results/32KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_zio.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 65536 -t set --threads 8 --csv -n 160000 >> /home/zio_ae/zIO/benchmarks/redis/results/64KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 131072 -t set --threads 8 --csv -n 40000 >> /home/zio_ae/zIO/benchmarks/redis/results/128KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &


ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d $((256*1024)) -t set --threads 8 --csv -n 40000 >> /home/zio_ae/zIO/benchmarks/redis/results/256KB_zio.dat"
sleep 60

pkill redis-server
sleep 5

rm /home/zio_ae/zIO/benchmarks/redis/pmem/*
./run_redis_other.sh &

ssh zio_ae@10.0.0.1 "cd redis/src; ./redis-benchmark -h 10.0.0.6 -p 7379 -d 524288 -t set --threads 8 --csv -n 10000 >> /home/zio_ae/zIO/benchmarks/redis/results/512KB_zio.dat"
sleep 60

pkill redis-server

echo "Processing..."
ssh zio_ae@10.0.0.1 "cd zIO/benchmarks/redis/results; reviewer_B/process.sh"

scp 10.0.0.1:~/zIO/benchmarks/redis/results/final.dat .
cat final.dat
rm final.dat
