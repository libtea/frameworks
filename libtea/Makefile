AS	   =  gcc
CC         =  gcc
#replace gcc below with your cross-compiler if compiling on x86
AARCH64_AS = gcc
AARCH64_CC = gcc
AARCH64_RECIPE = android
#comment out AARCH64_RECIPE if building natively on AArch64 Linux instead of cross-compiling for Android
CFLAGS += -Wall -Wno-unused-but-set-variable -Wno-unused-variable

#Below block of vars only needed if building an enclave recipe
URTS_LIB_PATH        = module/intel-sdk/linux-sgx/psw/urts/linux
ifndef $(SGX_SDK)
SGX_SDK              = /opt/intel/sgxsdk
endif
ifneq ($(SGX_SDK), /opt/intel/sgxsdk)
    URTS_LD_LIBRARY_PATH = URTS_LIB_PATH
endif
ENCLAVE_CFLAGS  = -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
ENCLAVE_INCLUDE = -I$(SGX_SDK)/include/
ENCLAVE_LDFLAGS = -ltea -lencl_proxy -lsgx_urts -lsgx_uae_service -pthread -Ltests/enclave/Enclave -L$(SGX_SDK)/lib64/ -L$(URTS_LIB_PATH) -L.


.PHONY: say-interrupts
say-interrupts:
	# ============================================================================================================
	# IMPORTANT: you MUST be booted with the following kernel command line parameters to avoid crashes when using
	# interrupts functionality:
	# nox2apic iomem=relaxed no_timer_check nosmep nosmap clearcpuid=514 isolcpus=1 nmi_watchdog=0
	#
	# Note that the "1" specified in isolcpus should be the CPU you lock your process to with libtea_pin_to_core
	# before using the interrupts functionality.
	#
	# You can pass these either (temporarily) by modifying them in the Grub boot menu at startup, or (persistently)
	# by modifying your Grub configuration:
	#
	# sudo vim /etc/default/grub
	# (add the command line parameters to the GRUB_CMDLINE_LINUX_DEFAULT="..." string)
	# sudo update-grub && reboot
	# =============================================================================================================
	sleep 5

.PHONY: say-enclave
say-enclave:
	# ====================================================================================================
	# IMPORTANT: Ensure you have run 'source /opt/intel/sgxsdk/environment' in your current shell, or this
	# Makefile will fail.
	#
	# Also ensure you have installed the (patched) SGX SDK:
	# git submodule init
	# git submodule update
	# ./module/install_SGX_driver.sh
	# ./module/install_SGX_SDK.sh
	#
	# To check the SGX aesmd service is running, use:
	# sudo service aesmd status
	# ====================================================================================================
	sleep 5

all: libtea-x86-paging

aarch64: libtea-aarch64-paging

libtea-x86-basic:
#The sed command below removes local includes only so these are resolved;
#otherwise the user has to deal with these at compile-time. We cannot
#preprocess to resolve global includes because then this results in
#redefinition errors if the user has any global includes.
#Note that each concatenated file *must* begin with a blank new line. If
#this is removed, you will encounter compile errors.
	rm -f libtea.h
	rm -f tests/test-basic
	cat ../LICENSE configs/basic_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h src/libtea_common.c src/arch/x86/libtea_x86_common.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_CACHE=0 -DLIBTEA_SUPPORT_PAGING=0"

libtea-x86-cache:
	rm -f libtea.h
	rm -f tests/test-basic
	rm -f tests/test-cache
	cat ../LICENSE configs/cache_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/libtea_cache.h src/libtea_common.c src/arch/x86/libtea_x86_common.c src/libtea_cache.c src/arch/x86/libtea_x86_cache.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	$(CC) $(CFLAGS) tests/test-cache.c -I. -o tests/test-cache
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_PAGING=0"

#Paging functionality depends on cache functionality
libtea-x86-paging:
	rm -f libtea.h
	rm -f tests/test-basic
	rm -f tests/test-cache
	rm -f tests/utest-paging/utest-paging
	cat ../LICENSE configs/cache_paging_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/libtea_cache.h include/arch/libtea_arch_paging.h include/arch/x86/libtea_x86_paging.h include/libtea_paging.h src/libtea_common.c src/arch/x86/libtea_x86_common.c src/libtea_cache.c src/arch/x86/libtea_x86_cache.c src/libtea_paging.c src/arch/x86/libtea_x86_paging.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	$(CC) $(CFLAGS) tests/test-cache.c -I. -o tests/test-cache
	make -C tests/utest-paging
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module

#Interrupt functionality depends on paging functionality
libtea-x86-interrupts: say-interrupts
	rm -f libtea.h
	rm -f libtea_irq_entry.o
	rm -f tests/test-basic
	rm -f tests/test-cache
	rm -f tests/utest-paging/utest-paging
	rm -f tests/test-interrupts
	$(AS) -o libtea_irq_entry.o -c src/arch/x86/asm/libtea_irq_entry.S
	cat ../LICENSE configs/cache_paging_interrupts_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/libtea_cache.h include/arch/libtea_arch_paging.h include/arch/x86/libtea_x86_paging.h include/libtea_paging.h include/libtea_interrupts.h src/libtea_common.c src/arch/x86/libtea_x86_common.c src/libtea_cache.c src/arch/x86/libtea_x86_cache.c src/libtea_paging.c src/arch/x86/libtea_x86_paging.c src/libtea_interrupts.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(ENCLAVE_CFLAGS) tests/test-basic.c libtea_irq_entry.o -I. -o tests/test-basic
	$(CC) $(ENCLAVE_CFLAGS) tests/test-cache.c libtea_irq_entry.o -I. -o tests/test-cache
	make -C tests/utest-paging test-interrupts
	$(CC) $(ENCLAVE_CFLAGS) tests/test-interrupts.c libtea_irq_entry.o -I. -o tests/test-interrupts
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_INTERRUPTS=1"

#Enclave functionality depends on interrupt functionality
libtea-x86-enclave: say-enclave
	rm -f libtea.h
	rm -f libtea_irq_entry.o
	rm -f libtea_aep_trampoline.o
	rm -f tests/test-basic
	rm -f tests/test-cache
	rm -f tests/utest-paging/utest-paging
	rm -f tests/test-interrupts
	rm -f tests/enclave/app
	rm -f tests/enclave/test-enclave.o
	rm -f tests/enclave/Enclave/*.o
	$(AS) -o libtea_irq_entry.o -c src/arch/x86/asm/libtea_irq_entry.S
	$(AS) -o libtea_aep_trampoline.o -c src/arch/x86/asm/libtea_aep_trampoline.S
	cat ../LICENSE configs/cache_paging_interrupts_enclave_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/libtea_cache.h include/arch/libtea_arch_paging.h include/arch/x86/libtea_x86_paging.h include/libtea_paging.h include/libtea_interrupts.h include/libtea_enclave.h src/libtea_common.c src/arch/x86/libtea_x86_common.c src/libtea_cache.c src/arch/x86/libtea_x86_cache.c src/libtea_paging.c src/arch/x86/libtea_x86_paging.c src/libtea_interrupts.c src/libtea_enclave.c FOOTER | sed 's/#include "libtea.*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(CFLAGS) $(ENCLAVE_CFLAGS) -o libtea.o -c libtea.h -I. $(ENCLAVE_INCLUDE)
	$(AR) rcs libtea.a libtea.o libtea_irq_entry.o libtea_aep_trampoline.o
	make -C tests/enclave
	$(CC) $(CFLAGS) $(ENCLAVE_CFLAGS) tests/test-basic.c libtea_irq_entry.o $(ENCLAVE_LDFLAGS) -I. $(ENCLAVE_INCLUDE) -o tests/test-basic
	$(CC) $(CFLAGS) $(ENCLAVE_CFLAGS) tests/test-cache.c libtea_irq_entry.o -I. $(ENCLAVE_INCLUDE) $(ENCLAVE_LDFLAGS) -o tests/test-cache
	make -C tests/utest-paging test-enclave CFLAGS="$(CFLAGS)" ENCLAVE_CFLAGS="$(ENCLAVE_CFLAGS)" ENCLAVE_INCLUDE="$(ENCLAVE_INCLUDE)" ENCLAVE_LDFLAGS="$(ENCLAVE_LDFLAGS)"
	$(CC) $(CFLAGS) $(ENCLAVE_CFLAGS) tests/test-interrupts.c libtea_irq_entry.o -I. $(ENCLAVE_INCLUDE) $(ENCLAVE_LDFLAGS) -o tests/test-interrupts
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_INTERRUPTS=1 -DLIBTEA_SUPPORT_ENCLAVE=1"

libtea-aarch64-basic:
	rm -f libtea.h
	rm -f tests/test-basic
	cat ../LICENSE configs/basic_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/arch/aarch64/libtea_aarch64_sysregs.h src/libtea_common.c src/arch/aarch64/libtea_aarch64_common.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(AARCH64_CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_CACHE=0 -DLIBTEA_SUPPORT_PAGING=0" $(AARCH64_RECIPE)

libtea-aarch64-cache:
	rm -f libtea.h
	rm -f tests/test-basic
	rm -f tests/test-cache
	cat ../LICENSE configs/cache_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/arch/aarch64/libtea_aarch64_sysregs.h include/libtea_cache.h src/libtea_common.c src/arch/aarch64/libtea_aarch64_common.c src/libtea_cache.c src/arch/aarch64/libtea_aarch64_cache.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(AARCH64_CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	$(AARCH64_CC) $(CFLAGS) tests/test-cache.c -I. -o tests/test-cache
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module KCPPFLAGS="-DLIBTEA_SUPPORT_CACHE=1 -DLIBTEA_SUPPORT_PAGING=0" $(AARCH64_RECIPE)

#Paging functionality depends on cache functionality
libtea-aarch64-paging:
	rm -f libtea.h
	rm -f tests/test-basic
	rm -f tests/test-cache
	rm -f tests/utest-paging/utest-paging
	cat ../LICENSE configs/cache_paging_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h include/arch/aarch64/libtea_aarch64_sysregs.h include/libtea_cache.h include/arch/libtea_arch_paging.h include/arch/aarch64/libtea_aarch64_paging.h include/libtea_paging.h src/libtea_common.c src/arch/aarch64/libtea_aarch64_common.c src/libtea_cache.c src/arch/aarch64/libtea_aarch64_cache.c src/libtea_paging.c src/arch/aarch64/libtea_aarch64_paging.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(AARCH64_CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic
	$(AARCH64_CC) $(CFLAGS) tests/test-cache.c -I. -o tests/test-cache
	make -C tests/utest-paging
	make -C module LIBTEA_KERNEL_BUILD_DIR=$(PWD)/module $(AARCH64_RECIPE)

#Interrupt and enclave functionality not yet supported on AArch64

libtea-ppc64-basic:
	rm -f libtea.h
	rm -f tests/test-basic
	cat ../LICENSE configs/basic_config.h libtea_config.h module/libtea_ioctl.h include/libtea_common.h include/arch/libtea_arch.h src/libtea_common.c src/arch/ppc64/libtea_ppc64_common.c FOOTER | sed 's/#include ".*"//g' > libtea.h
	cp libtea.h doc/libtea.h
	$(CC) $(CFLAGS) tests/test-basic.c -I. -o tests/test-basic

#Cache, paging, interrupt, and enclave functionality not yet supported on PPC64
