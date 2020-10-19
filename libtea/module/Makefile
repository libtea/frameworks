obj-m += libtea.o
CROSS_COMPILE_KERNEL=your-aarch64-linux-android-compiler-path-here
ANDROID_KERNEL_DIR=your-android-kernel-path-here

ifndef $(LIBTEA_KERNEL_BUILD_DIR)
LIBTEA_KERNEL_BUILD_DIR = $(PWD)
endif

all: clean_linux linux

linux:
	make -C /lib/modules/$(shell uname -r)/build M=$(LIBTEA_KERNEL_BUILD_DIR) modules

clean_linux:
	make -C /lib/modules/$(shell uname -r)/build M=$(LIBTEA_KERNEL_BUILD_DIR) clean

android:
	make -C $(ANDROID_KERNEL_DIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE_KERNEL) modules

clean_android:
	make -C $(ANDROID_KERNEL_DIR) M=$(PWD) clean
