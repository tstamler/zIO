# zIO - Transparent Zero Copy IO Library <!-- omit in toc -->

- [1. System requirements (Tested environment)](#1-system-requirements-tested-environment)
- [2. Dependent package installation](#2-dependent-package-installation)
- [3. Hardware setup](#3-hardware-setup)
- [4. Download source code](#4-download-source-code)
- [5. Compiling zIO](#5-compiling-zIO)
- [6. Running zIO benchmarks](#11-running-zIO-benchmarks)
- [7. Compiling kernel bypass stacks](#5-compiling-kernel-bypass)
- [8. Running zIO+IO and kernel bypass benchmarks](#11-running-kernel-bypass-benchmarks)

## 1. System requirements (Tested environment)

### 1.1. Hardware requirements

- 24 cores per NUMA node
- 196 GB DRAM
- 6 NVDIMM persistent memory per NUMA node

### 1.2. Software requirements

- Ubuntu 20.04
- Linux kernel version: 5.10.0
- Mellanox OFED driver version: 4.7


## 2. Dependent package installation

```shell
sudo apt install build-essential make pkg-config autoconf libnuma-dev libaio1 libaio-dev uuid-dev librdmacm-dev ndctl numactl libncurses-dev libssl-dev libelf-dev rsync
```

## 3. Hardware setup

### 3.1. Persistent memory configuration

> If your system does not have persistent memory, you need to emulate it using DRAM. Refer to [How to Emulate Persistent Memory Using Dynamic Random-access Memory (DRAM)](https://software.intel.com/content/www/us/en/develop/articles/how-to-emulate-persistent-memory-on-an-intel-architecture-server.html) for persistent memory emulation.

When running the storage benchmarks, zIO is run with either Strata, a kernel bypass storage stack, or Linux EXT4-DAX. Both use persistent memory as storage and it needs to be configured as Device-DAX mode. Make sure that the created namespace has enough size. It must be larger than the size reserved by LineFS (`dev_size` in `libfs/src/storage/storage.h`). A command for creating a new namespace is as below.

```shell
sudo ndctl create-namespace -m dax --region=region0 --size=132G
```

Now, you can find out DAX devices under `/dev` directory as below.

```shell
$ ls /dev/dax*
/dev/dax0.0  /dev/dax0.1
```

## 4. Download source code

```shell
git clone git@github.com:tstamler/zIO.git
cd zIO
```

## 5. Compiling zIO

```shell
cd zIO
make clean
make
```

## 6. Running benchmarks

zIO without any kernel bypass stacks can be run with LD_PRELOAD of the copy_interpose.so file on top of most existing applications. 

Here is a quick summary of the benchmarks and where they appear in the paper. The scripts directory is commented and provides more information and examples on how to run these specific applications.

- Copy Sweep: We keep the message size constant and vary the number of copies done per request. (Figure 4) 
- Size Sweep: We keep the number of copies constant and vary the size of the messages. (Figure 6) 
- Thread Sweep: We increase the number of threads to demonstrate that zIO does not impose overhead. (Figure 8) 
- Page Fault Test: This is a special microbenchmark where zIO forces an unmapping and variable number of page faults. This should demonstrate the overheads of handling each of the page faults. (Figure 10) 
- Redis SETS: We run Redis with all SET requests to show the benefits of zIO with Linux. (Figure 11)

## 7. Compiling kernel bypass stacks

### 7.1 Compiling Strata

Instructions for compiling and mounting Strata can be found here:
https://github.com/ut-osa/strata

You may use the version of Strata included in this repository. We only configure Strata to run only with non-volatile memory, and not SSD or HDD. 

### 7.2 Compiling TAS and zIO+IO 

Instructions for compiling and running TAS can be found here:
https://github.com/tcp-acceleration-service/tas

When running TAS, tcp-txbuf-len and tcp-rxbuf-len must be set to large values, at least the message size for the benchmark you are trying to run, preferably multiple times the message length. Without this, you may not be able to correctly run with optimistic receiver persistence. 

### 8. Running kernel bypass stacks

When you build the version of TAS included in this repository, it will build a few files:

- The page_fault_test.so file, which we use to run the page faulting benchmarks described earlier. 
- The mem_counter.so file, which we use the count the number of memory copies in applications.
- The zio_interpose.so file, which will run zIO with kernel bypass stack integration (zIO+IO and zIO+ORP). Note that you must be running both the versions of TAS and Strata in this repository for benchmarks to function correctly. The benchmarks may still run, but the data would be incorrect. 

Examples of how to run these cases coming soon...

### 9. Other branchs

- You should primarily be using the master branch. 
- ae_client and ae_server are specific branchs we created for OSDI '22 Artifact Evaluation. 
- The mongo branch is being used to upgrade our Strata implementation to Assise and integrate zIO+IO and zIO+ORP with MongoDB
- All other branches are deprecated and should be soon removed
