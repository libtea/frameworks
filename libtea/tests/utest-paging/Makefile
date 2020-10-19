all: test

test: utest-paging.c utest.h
	gcc utest-paging.c -o utest-paging -fsanitize=address

test-interrupts: utest-paging.c utest.h
	gcc utest-paging.c ../../libtea_irq_entry.o -o utest-paging -fsanitize=address

test-enclave:
	gcc $(CFLAGS) $(ENCLAVE_CFLAGS) utest-paging.c ../../libtea_irq_entry.o -I. -I../../ $(ENCLAVE_INCLUDE) $(ENCLAVE_LDFLAGS) -L../../ -L../enclave/Enclave -o utest-paging -fsanitize=address

clean:
	rm -f utest-paging
