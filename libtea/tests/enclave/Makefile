LIBTEA_DIR           = ../../
URTS_LIB_PATH        = ../../module/intel-sdk/linux-sgx/psw/urts/linux

ifndef $(SGX_SDK)
SGX_SDK              = /opt/intel/sgxsdk
endif
ifneq ($(SGX_SDK), /opt/intel/sgxsdk)
    URTS_LD_LIBRARY_PATH = URTS_LIB_PATH
endif

ENCLAVE              = Enclave
SUBDIRS              = $(ENCLAVE)

CC                   = gcc
AS                   = gcc
LD                   = gcc

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
INCLUDE              = -I$(SGX_SDK)/include/ -I$(LIBTEA_DIR)
LDFLAGS             += -ltea -lencl_proxy -lsgx_urts \
                       -lsgx_uae_service -pthread $(SUBDIRS:%=-L %) -L$(SGX_SDK)/lib64/ \
                       -L$(URTS_LIB_PATH) -L$(LIBTEA_DIR)

SOURCES              = $(shell ls *.c)
OBJECTS              = $(SOURCES:.c=.o)
OUTPUT               = app

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

all: say $(OUTPUT)

.PHONY: say
say:
	# IMPORTANT: Ensure you have run 'source /opt/intel/sgxsdk/environment' in your current shell, or this Makefile will fail
	#

run: clean all
	sudo $(URTS_LD_LIBRARY_PATH) ./$(OUTPUT)

debug: clean all
	sudo `which sgx-gdb` && ./$(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT)

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" M32=$(M32) curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
