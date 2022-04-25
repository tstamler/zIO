#!/bin/bash

sed -i 1,5d 8KB.dat

echo "Linux Results: " >> final.dat

echo "8KB: $( awk '{ total += $1; count++ } END { print total/count }' 8KB.dat ) mbps" >> final.dat

sed -i 1,5d 16KB.dat

echo "16KB: $( awk '{ total += $1; count++ } END { print total/count }' 16KB.dat ) mbps" >> final.dat

sed -i 1,5d 32KB.dat

echo "32KB: $( awk '{ total += $1; count++ } END { print total/count }' 32KB.dat ) mbps" >> final.dat

sed -i 1,5d 64KB.dat

echo "64KB: $( awk '{ total += $1; count++ } END { print total/count }' 64KB.dat ) mbps" >> final.dat

sed -i 1,5d 128KB.dat

echo "128KB: $( awk '{ total += $1; count++ } END { print total/count }' 128KB.dat ) mbps" >> final.dat

sed -i 1,5d 256KB.dat

echo "256KB: $( awk '{ total += $1; count++ } END { print total/count }' 256KB.dat ) mbps" >> final.dat

echo "zIO Results: " >> final.dat

sed -i 1,5d 8KB_zio.dat

echo "8KB: $( awk '{ total += $1; count++ } END { print total/count }' 8KB_zio.dat ) mbps" >> final.dat

sed -i 1,5d 16KB_zio.dat

echo "16KB: $( awk '{ total += $1; count++ } END { print total/count }' 16KB_zio.dat ) mbps" >> final.dat

sed -i 1,5d 32KB_zio.dat

echo "32KB: $( awk '{ total += $1; count++ } END { print total/count }' 32KB_zio.dat ) mbps" >> final.dat

sed -i 1,5d 64KB_zio.dat

echo "64KB: $( awk '{ total += $1; count++ } END { print total/count }' 64KB_zio.dat ) mbps" >> final.dat

sed -i 1,5d 128KB_zio.dat

echo "128KB: $( awk '{ total += $1; count++ } END { print total/count }' 128KB_zio.dat ) mbps" >> final.dat

sed -i 1,5d 256KB_zio.dat

echo "256KB: $( awk '{ total += $1; count++ } END { print total/count }' 256KB_zio.dat ) mbps" >> final.dat


