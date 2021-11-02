#! /bin/bash

PATH=$PATH:.
SRC_ROOT=../../../
export LD_LIBRARY_PATH=$SRC_ROOT/libfs/lib/nvml/src/nondebug/:$SRC_ROOT/libfs/build
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 MLFS_DEBUG=1 $@
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 MLFS_PROFILE=1 $@
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 MLFS_PROFILE=1 taskset -c 0,7 $@
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 taskset -c 0,7 $@
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 MLFS_PROFILE=1 $@
LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/libtas_interpose.so MLFS=1 /home/tstamler/stratas_dev/strata/bench/redis-3.2.8/src/redis-server.mlfs ../redis_mlfs.conf #2> err_out 
#LD_PRELOAD=/home/tstamler/stratas_dev/tas/lib/libtas_interpose.so MLFS=1 /home/tstamler/stratas_dev/strata/bench/redis-3.2.8/src/redis-server.mlfs ../redis_mlfs.conf  
#LD_PRELOAD=$SRC_ROOT/shim/libshim/libshim.so MLFS=1 /home/tstamler/mlfs/bench/redis-3.2.8/src/redis-server.mlfs ../redis_mlfs.conf  
