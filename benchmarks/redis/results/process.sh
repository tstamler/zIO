#!/bin/bash

rm final.dat
sed -i 1,1d *.dat

echo "Linux Results: " >> final.dat

echo "4KB: $( awk -F'"' '{print $4}' 4KB.dat ) req/s" >> final.dat

echo "Linux Results: " >> final.dat

echo "16KB: $( awk -F'"' '{print $4}' 16KB.dat ) req/s" >> final.dat

echo "Linux Results: " >> final.dat

echo "64KB: $( awk -F'"' '{print $4}' 64KB.dat ) req/s" >> final.dat

echo "Linux Results: " >> final.dat

echo "128KB: $( awk -F'"' '{print $4}' 128KB.dat ) req/s" >> final.dat

echo "Linux Results: " >> final.dat

echo "512KB: $( awk -F'"' '{print $4}' 512KB.dat ) req/s" >> final.dat

