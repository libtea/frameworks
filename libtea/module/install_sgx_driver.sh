#!/bin/bash
#From SGX-Step by Jo Van Bulck (2017-2020), released under GNU GPL v3.0

set -e

git submodule init
git submodule update
cd linux-sgx-driver

# ----------------------------------------------------------------------
sudo apt-get -yqq install linux-headers-$(uname -r)
make
sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules" 
sudo /sbin/depmod
sudo /sbin/modprobe isgx

echo "SGX driver succesfully installed"
