#!/bin/bash
sudo apt-get update
cd module
bash -x ./install_SGX_driver.sh
bash -x ./install_SGX_SDK.sh