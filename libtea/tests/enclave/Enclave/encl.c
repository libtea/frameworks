// From SGX-Step by Jo Van Bulck (2017-2020), released under GNU GPL v3.0

__attribute__((aligned(4096))) int array[4096] = {0xaa};
#define a array[0]

void* get_a_addr(void)
{
    return &a;
}

int enclave_dummy_call(void)
{
    return a;
}
