
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_ENCLAVE_H
#define LIBTEA_ENCLAVE_H

#include "libtea_common.h"
#include "libtea_paging.h"
#include "libtea_interrupts.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Summary of the sequence of hardware and software steps when interrupting and resuming an SGX enclave through our framework:
 * 1) The local APIC timer interrupt arrives within an enclaved instruction.
 * 2) The processor executes the AEX (Asynchronous Enclave Exit) procedure that securely stores execution context in the enclave’s
 * State Save Area (SSA) frame, initializes CPU registers, and vectors to the (user space) interrupt handler registered in the 
 * Interrupt Descriptor Table (IDT).
 * 3) At this point, any attack-specific, spy code can easily be plugged in.
 * 4) The library returns to the user space AEP (Asynchronous Exit Procedure) trampoline. If you use the SGX-Step modified version
 * of the SGX SDK, it allows easy registration of a custom AEP stub. Furthermore, to enable precise evaluation on attacker-controlled
 * benchmark debug enclaves, the framework can optionally retrieve the stored instruction pointer from the interrupted enclave’s SSA frame. 
 * 5) Thereafter, we configure the local APIC timer for the next interrupt by writing into the initial-count MMIO register.
 * 6) ERESUME is executed to return to the enclave.
 *
 * See the SGX-Step repository (https://github.com/jovanbulck/sgx-step) for setup instructions and details of the SGX-Step modified
 * version of the SGX SDK.
 *
 * The following functions are non-standard and depend on the modified version of the SGX SDK:
 * sgx_get_aep(void);
 * sgx_set_aep(void *aep);
 * sgx_get_tcs(void);
 * sgx_set_load_ptr(void *load_ptr);
 *
 * Other relevant terminology:
 * TCS = Thread Control Structure
 * GPRSGX = region of the SSA where SGX general-purpose register state is stored
 * OSSA = State Save Area Offset (TCS.OSSA).
 */

/* Currently the only supported enclave type is Intel SGX, but here for future expansion */
#if LIBTEA_SUPPORT_SGX

/* NOTE: incorrect GPRSGX size in Intel manual vol. 3D June 2016 p.38-7 */
#define LIBTEA_SGX_TCS_OSSA_OFFSET         16
#define LIBTEA_SGX_GPRSGX_SIZE             184
#define LIBTEA_SGX_GPRSGX_RIP_OFFSET       136

/* HACK: to avoid having to retrieve the SSA framesize from the untrusted
   runtime (driver), we assume a standard/hard-coded SSA framesize of 1 page */
#define LIBTEA_SGX_SSAFRAMESIZE            4096

/* Includes custom AEP get/set functions from patched SGX SDK urts. */
#include "sgx_error.h"
#include "sgx_urts.h"
#include <inttypes.h>

extern uint32_t libtea_tsc_eresume, libtea_tsc_aex;
extern int libtea_eresume_cnt;
typedef void (*libtea_aep_function_t)(void);

struct libtea_sgx_regs {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    uint32_t exitinfo;
    uint32_t reserved;
    uint64_t fsbase;
    uint64_t gsbase;
};

typedef union {
    struct libtea_sgx_regs fields;
    uint8_t bytes[ sizeof(struct libtea_sgx_regs) ];
} libtea_gprsgx_state;

typedef union {
    uint8_t bytes[8];
    uint64_t reg;
} regs;

typedef struct {
  uint64_t base;
  uint64_t size;
  uint64_t aep;
  uint64_t tcs;
} libtea_enclave_info;


/**
 * Registers a custom function to run during the AEP trampoline (optional).
 * The function can be entirely arbitrary - it does not need to handle any AEP-specific
 * state or tasks.
 *
 * :param custom_function: Function to use
 */
void libtea_register_custom_aep_function(libtea_aep_function_t custom_function);


/**
 * Initalizes the provided enclave struct so it can be used by other libtea enclave functions.
 * The struct is initalized using information from SGX.
 *
 * :param instance: The libtea instance
 * :param enclave: An enclave info struct
 */
void libtea_init_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave);


/**
 * Returns a pointer to the base address of the enclave.
 *
 * :param enclave: An initalized enclave info struct
 * :return: Pointer to the base address
 */
void* libtea_get_enclave_base(libtea_enclave_info* enclave);


/**
 * Returns the size of the enclave.
 *
 * :param enclave: An initalized enclave info struct
 * :return: Enclave size
 */
int libtea_get_enclave_size(libtea_enclave_info* enclave);


/**
 * Prints the following information about the enclave to stdout: the address of its base,
 * limit, TCS, SSA-GPRSGX, and AEP; its size; and whether it is a debug or production enclave.
 *
 * :param instance: The libtea instance
 * :param enclave: An initalized enclave info struct
 */
void libtea_print_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave);


/**
 * Returns a pointer to the GPRSGX region in the enclave's SSA frame, where it saves its
 * state upon being interrupted.
 *
 * :param instance: The libtea instance
 * :param enclave: An initialized enclave info struct
 * :return: Pointer to the enclave's SSA-GPRSGX region
 */
void* libtea_get_gprsgx_address(libtea_instance* instance, libtea_enclave_info* enclave);


/*
 * Prints the provided GPRSGX state to stdout.
 *
 * :param sgx_state: Stored GPRSGX state
 */
void libtea_print_gprsgx_state(libtea_gprsgx_state *sgx_state);


/* Helper function, not in API */
void libtea_rw_secure_addr(libtea_instance* instance, void *addr, void* value, int len, int write);


/**
 * Reads from an address in a Trusted Execution Environment.
 *
 * Note: currently only supported for SGX debug enclaves.
 *
 * :param instance: The libtea instance
 * :param addr: The address
 * :param value: Variable to write the read value to
 * :param len: Number of bytes to read
 */
#define libtea_read_secure_addr(instance, addr, value, len)  libtea_rw_secure_addr(instance, addr, value, len, 0)


/**
 * Writes to an address in a Trusted Execution Environment.
 *
 * Note: currently only supported for SGX debug enclaves.
 *
 * :param instance: The libtea instance
 * :param addr: The address
 * :param value: Variable containing the value to write
 * :param len: Number of bytes to write
 */
#define libtea_write_secure_addr(instance, addr, value, len)  libtea_rw_secure_addr(instance, addr, value, len, 1)


/**
 * Reads from the interrupted enclave's SSA frame at the provided offset.
 *
 * Note: as this uses the EDBGRD (Read from a Debug Enclave) instruction, it will only work with debug enclaves.
 *
 * :param instance: The libtea instance
 * :param enclave: An initalized enclave info struct
 * :param ssa_field_offset: Offset within the SSA frame
 * :return: The value at the provided offset
 */
uint64_t libtea_read_ssa_at_offset(libtea_instance* instance, libtea_enclave_info* enclave, int ssa_field_offset);


/**
 * Retrieves the stored instruction pointer (ERIP) from the interrupted enclave's SSA frame.
 *
 * Note: as this uses the EDBGRD (Read from a Debug Enclave) instruction, it will only work with debug enclaves.
 *
 * :param instance: The libtea instance
 * :param enclave: An initialized enclave info struct
 * :return: The stored enclave instruction pointer (ERIP)
 */
#define libtea_get_erip(instance, enclave) libtea_read_ssa_at_offset(instance, enclave, LIBTEA_SGX_GPRSGX_RIP_OFFSET)


#define libtea_sgx_assert(f)  { if (SGX_SUCCESS != f) {               \
   printf( "Error calling enclave at %s:%d\n", __FILE__, __LINE__);   \
   abort();                                                           \
 } }

#endif //LIBTEA_SUPPORT_SGX

#ifdef __cplusplus
}
#endif

#endif //LIBTEA_ENCLAVE_H
