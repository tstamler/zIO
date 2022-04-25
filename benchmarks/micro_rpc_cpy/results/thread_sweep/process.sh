#!/bin/bash

sed -i 1,5d 1thread.dat

echo "Linux Results: " >> final.dat

echo "One Thread: $( awk '{ total += $1; count++ } END { print total/count }' 1thread.dat ) mbps" >> final.dat

sed -i 1,5d 2thread.dat

echo "Two Thread: $( awk '{ total += $1; count++ } END { print total/count }' 2thread.dat ) mbps" >> final.dat

sed -i 1,5d 4thread.dat

echo "Four Thread: $( awk '{ total += $1; count++ } END { print total/count }' 4thread.dat ) mbps" >> final.dat

sed -i 1,5d 8thread.dat

echo "Eight Thread: $( awk '{ total += $1; count++ } END { print total/count }' 8thread.dat ) mbps" >> final.dat

echo "zIO Results: " >> final.dat

sed -i 1,5d 1thread_zio.dat

echo "One Thread: $( awk '{ total += $1; count++ } END { print total/count }' 1thread_zio.dat ) mbps" >> final.dat

sed -i 1,5d 2thread_zio.dat

echo "Two Thread: $( awk '{ total += $1; count++ } END { print total/count }' 2thread_zio.dat ) mbps" >> final.dat

sed -i 1,5d 4thread_zio.dat

echo "Four Thread: $( awk '{ total += $1; count++ } END { print total/count }' 4thread_zio.dat ) mbps" >> final.dat

sed -i 1,5d 8thread_zio.dat

echo "Eight Thread: $( awk '{ total += $1; count++ } END { print total/count }' 8thread_zio.dat ) mbps" >> final.dat

