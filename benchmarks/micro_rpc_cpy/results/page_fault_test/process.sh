#!/bin/bash

sed -i 1,5d 0fault.dat

echo "Linux Results: " >> final.dat

echo "Zero Faults: $( awk '{ total += $1; count++ } END { print total/count }' 0fault.dat ) mbps" >> final.dat

sed -i 1,5d 1fault.dat

echo "One Fault: $( awk '{ total += $1; count++ } END { print total/count }' 1fault.dat ) mbps" >> final.dat

sed -i 1,5d 2fault.dat

echo "Two Fault: $( awk '{ total += $1; count++ } END { print total/count }' 2fault.dat ) mbps" >> final.dat

sed -i 1,5d 4fault.dat

echo "Four Fault: $( awk '{ total += $1; count++ } END { print total/count }' 4fault.dat ) mbps" >> final.dat

sed -i 1,5d 8fault.dat

echo "Eight Fault: $( awk '{ total += $1; count++ } END { print total/count }' 8fault.dat ) mbps" >> final.dat

sed -i 1,5d 12fault.dat

echo "Twelve Fault: $( awk '{ total += $1; count++ } END { print total/count }' 12fault.dat ) mbps" >> final.dat

echo "zIO Results: " >> final.dat

sed -i 1,5d 0fault_zio.dat

echo "Zero Fault: $( awk '{ total += $1; count++ } END { print total/count }' 0fault_zio.dat ) mbps" >> final.dat

sed -i 1,5d 1fault_zio.dat

echo "One Fault: $( awk '{ total += $1; count++ } END { print total/count }' 1fault_zio.dat ) mbps" >> final.dat

sed -i 1,5d 2fault_zio.dat

echo "Two Fault: $( awk '{ total += $1; count++ } END { print total/count }' 2fault_zio.dat ) mbps" >> final.dat

sed -i 1,5d 4fault_zio.dat

echo "Four Fault: $( awk '{ total += $1; count++ } END { print total/count }' 4fault_zio.dat ) mbps" >> final.dat

sed -i 1,5d 8fault_zio.dat

echo "Eight Fault: $( awk '{ total += $1; count++ } END { print total/count }' 8fault_zio.dat ) mbps" >> final.dat

sed -i 1,5d 12fault_zio.dat

echo "Twelve Fault: $( awk '{ total += $1; count++ } END { print total/count }' 12fault_zio.dat ) mbps" >> final.dat


