#!/bin/bash

sed -i 1,5d 0copy.dat

echo "Linux Results: " >> final.dat

echo "Zero Copy: $( awk '{ total += $1; count++ } END { print total/count }' 0copy.dat ) mbps" >> final.dat

sed -i 1,5d 1copy.dat

echo "One Copy: $( awk '{ total += $1; count++ } END { print total/count }' 1copy.dat ) mbps" >> final.dat

sed -i 1,5d 2copy.dat

echo "Two Copy: $( awk '{ total += $1; count++ } END { print total/count }' 2copy.dat ) mbps" >> final.dat

sed -i 1,5d 4copy.dat

echo "Four Copy: $( awk '{ total += $1; count++ } END { print total/count }' 4copy.dat ) mbps" >> final.dat

sed -i 1,5d 8copy.dat

echo "Eight Copy: $( awk '{ total += $1; count++ } END { print total/count }' 8copy.dat ) mbps" >> final.dat

sed -i 1,5d 12copy.dat

echo "Twelve Copy: $( awk '{ total += $1; count++ } END { print total/count }' 12copy.dat ) mbps" >> final.dat

echo "zIO Results: " >> final.dat

sed -i 1,5d 0copy_zio.dat

echo "Zero Copy: $( awk '{ total += $1; count++ } END { print total/count }' 0copy_zio.dat ) mbps" >> final.dat

sed -i 1,5d 1copy_zio.dat

echo "One Copy: $( awk '{ total += $1; count++ } END { print total/count }' 1copy_zio.dat ) mbps" >> final.dat

sed -i 1,5d 2copy_zio.dat

echo "Two Copy: $( awk '{ total += $1; count++ } END { print total/count }' 2copy_zio.dat ) mbps" >> final.dat

sed -i 1,5d 4copy_zio.dat

echo "Four Copy: $( awk '{ total += $1; count++ } END { print total/count }' 4copy_zio.dat ) mbps" >> final.dat

sed -i 1,5d 8copy_zio.dat

echo "Eight Copy: $( awk '{ total += $1; count++ } END { print total/count }' 8copy_zio.dat ) mbps" >> final.dat

sed -i 1,5d 12copy_zio.dat

echo "Twelve Copy: $( awk '{ total += $1; count++ } END { print total/count }' 12copy_zio.dat ) mbps" >> final.dat


