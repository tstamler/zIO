Thank you for reviewing our artifacts!

We have a server machine available for you to run experiments on. The first thing we will need is an ssh public key so that you can get access.

After that, the machines can be accessed with the following command:
ssh zio_ae@pig.csres.utexas.edu\

This will take you to the main server machine. The appropriate code and benchmarks will be located in the zIO directory. Everything should already be built and ready to run, you just need to go to the zIO/scripts directory and run the different scripts there for the different benchmarks. If you want, you can run make clean and make to rebuild parts of the benchmarks in the appropriate directories. Each script should take no more than 10-15 minutes to complete. 

Here is a quick summary of the benchmarks and where they appear in the paper. The scripts will be commented and provide more information. 

Copy Sweep: We keep the message size constant and vary the number of copies done per request. (Figure 4)
Size Sweep: We keep the number of copies constant and vary the size of the messages. (Figure 6)
Thread Sweep: We increase the number of threads to demonstrate that zIO does not impose overhead. (Figure 8)
Page Fault Test: This is a special microbenchmark where zIO forces an unmapping and variable number of page faults. This should demonstrate the overheads of handling each of the page faults. (Figure 10)
Redis SETS: We run Redis with all SET requests to show the benefits of zIO with Linux. (Figure 11)

Thank you again!
Tim Stamler, on behalf of the zIO authors
