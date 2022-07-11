
The zIO library can built simply with make in the main directory. This will generate a copy_interpose.so file that can be LD_PRELOADed on top of the exisiting applications. See the scripts directory for examples. 

Here is a quick summary of the benchmarks and where they appear in the paper. The scripts will be commented and provide more information. 

Copy Sweep: We keep the message size constant and vary the number of copies done per request. (Figure 4)
Size Sweep: We keep the number of copies constant and vary the size of the messages. (Figure 6)
Thread Sweep: We increase the number of threads to demonstrate that zIO does not impose overhead. (Figure 8)
Page Fault Test: This is a special microbenchmark where zIO forces an unmapping and variable number of page faults. This should demonstrate the overheads of handling each of the page faults. (Figure 10)
Redis SETS: We run Redis with all SET requests to show the benefits of zIO with Linux. (Figure 11)

