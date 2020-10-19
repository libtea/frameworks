#!/bin/bash
#From SGX-Step by Jo Van Bulck (2017-2020), released under GNU GPL v3.0

cd intel-sdk/linux-sgx

echo "=== patching AEP/TCS/EBASE ==="
patch -p1 < ../0001-reconfigure-AEP-TCS-ebase.patch