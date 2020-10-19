
/* See LICENSE file for license and copyright information */

/* Start libtea_enclave.c */
//---------------------------------------------------------------------------
#include "libtea_enclave.h"
#include <errno.h>


/* These functions are implemented in the SGX SDK, provided the SGX-Step patch is installed.
 * You must link your binary to the patched SDK in addition to including the Libtea header if
 * you wish to use Enclave functionality.
 */
extern void* SGXAPI sgx_get_aep(void);
extern void SGXAPI sgx_set_aep(void *aep);
extern void* SGXAPI sgx_get_tcs(void);


/* See aep_trampoline.S to see how these are used. */
extern void libtea_aep_trampoline(void);
libtea_aep_function_t libtea_aep_function = NULL;
uint64_t libtea_tcs    = 0x0;
uint32_t libtea_tsc_eresume = 0x0;
int libtea_eresume_cnt = 0;


void libtea_register_custom_aep_function(libtea_aep_function_t custom_function){
  sgx_set_aep(libtea_aep_trampoline);
  libtea_aep_function = custom_function; /* Used by libtea_aep_trampoline in aep_trampoline.S */
}


void libtea_init_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave){
  enclave->tcs = (uint64_t) sgx_get_tcs();
  enclave->aep = (uint64_t) sgx_get_aep();

  libtea_assert(instance != NULL);
  libtea_assert(instance->module_fd > 0);
  libtea_assert(instance->umem_fd > 0);
  libtea_assert(enclave != NULL);
  libtea_assert(ioctl(instance->module_fd, LIBTEA_IOCTL_ENCLAVE_INFO, enclave) >= 0);
}


void* libtea_get_enclave_base(libtea_enclave_info* enclave){
  return (void*)((uintptr_t) enclave->base);
}


int libtea_get_enclave_size(libtea_enclave_info* enclave){
  return (int) enclave->size;
}


void libtea_print_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave){

  uint64_t read = 0xff;

  printf("==== Enclave ====\n" );
  printf("Base:          %p\n", libtea_get_enclave_base(enclave));
  printf("Size:          %d\n", (int) enclave->size);
  printf("Limit:         %p\n", libtea_get_enclave_base(enclave) + (int) enclave->size);
  printf("TCS:           %p\n", sgx_get_tcs());
  printf("SSA-GPRSGX:    %p\n", libtea_get_gprsgx_address(instance, enclave));
  printf("AEP:           %p\n", sgx_get_aep());

  /* First 8 bytes of TCS must be zero */
  libtea_read_enclave_addr(instance, sgx_get_tcs(), &read, 8); /* We use failure here to determine it's a production enclave - the only case where it doesn't need to be a debug enclave */
  printf("EDBGRD:        %s\n", read ? "Production" : "Debug");
}


void* libtea_get_gprsgx_address(libtea_instance* instance, libtea_enclave_info* enclave){
  static uint64_t ossa = 0x0;   /* Cache OSSA value to avoid repeated IOCTLs */
  void *tcs_addr = sgx_get_tcs();

  if (!ossa) {
    libtea_read_enclave_addr(instance, tcs_addr + LIBTEA_SGX_TCS_OSSA_OFFSET, &ossa, 8);
  }

  return libtea_get_enclave_base(enclave) + ossa + LIBTEA_SGX_SSAFRAMESIZE - LIBTEA_SGX_GPRSGX_SIZE;
}


void libtea_print_gprsgx_state(libtea_gprsgx_state *gprsgx_state){
  printf("=== SSA-GPRSGX region ===\n");
  printf("RAX:      0x%" PRIx64 "\n", gprsgx_state->fields.rax);
  printf("RCX:      0x%" PRIx64 "\n", gprsgx_state->fields.rcx);
  printf("RDX:      0x%" PRIx64 "\n", gprsgx_state->fields.rdx);
  printf("RBX:      0x%" PRIx64 "\n", gprsgx_state->fields.rbx);
  printf("RSP:      0x%" PRIx64 "\n", gprsgx_state->fields.rsp);
  printf("RBP:      0x%" PRIx64 "\n", gprsgx_state->fields.rbp);
  printf("RSI:      0x%" PRIx64 "\n", gprsgx_state->fields.rsi);
  printf("RDI:      0x%" PRIx64 "\n", gprsgx_state->fields.rdi);
  printf("R8:       0x%" PRIx64 "\n", gprsgx_state->fields.r8);
  printf("R9:       0x%" PRIx64 "\n", gprsgx_state->fields.r9);
  printf("R10:      0x%" PRIx64 "\n", gprsgx_state->fields.r10);
  printf("R11:      0x%" PRIx64 "\n", gprsgx_state->fields.r11);
  printf("R12:      0x%" PRIx64 "\n", gprsgx_state->fields.r12);
  printf("R13:      0x%" PRIx64 "\n", gprsgx_state->fields.r13);
  printf("R14:      0x%" PRIx64 "\n", gprsgx_state->fields.r14);
  printf("R15:      0x%" PRIx64 "\n", gprsgx_state->fields.r15);
  printf("RFLAGS:   0x%" PRIx64 "\n", gprsgx_state->fields.rflags);
  printf("RIP:      0x%" PRIx64 "\n", gprsgx_state->fields.rip);
  printf("URSP:     0x%" PRIx64 "\n", gprsgx_state->fields.ursp);
  printf("URBP:     0x%" PRIx64 "\n", gprsgx_state->fields.urbp);
  printf("EXITINFO: 0x%" PRIu32 "\n", gprsgx_state->fields.exitinfo);
  printf("FSBASE:   0x%" PRIx64 "\n", gprsgx_state->fields.fsbase);
  printf("GSBASE:   0x%" PRIx64 "\n", gprsgx_state->fields.gsbase);
}


void libtea_rw_enclave_addr(libtea_instance* instance, void *addr, void* value, int len, int write){
  libtea_edbgrd edbgrd_data = {
    .adrs = (uintptr_t) addr,
    .val = (uintptr_t) value,
    .len = (int64_t) len,
    .write = write
  };

  if(ioctl(instance->module_fd, LIBTEA_IOCTL_EDBGRD, &edbgrd_data) < 0){
    libtea_info("Error: failed to read/write enclave address. IOCTL error: %d", errno);
  }
}


uint64_t libtea_read_ssa_at_offset(libtea_instance* instance, libtea_enclave_info* enclave, int ssa_field_offset){
  static uint64_t ossa = 0x0;   /* Cache OSSA value to avoid repeated IOCTLs */
  uint64_t ret;
  void *ssa_field_addr, *tcs_addr = sgx_get_tcs();

  if(!ossa){
    libtea_read_enclave_addr(instance, tcs_addr + LIBTEA_SGX_TCS_OSSA_OFFSET, &ossa, 8);
  }
  ssa_field_addr = libtea_get_enclave_base(enclave) + ossa + LIBTEA_SGX_SSAFRAMESIZE - LIBTEA_SGX_GPRSGX_SIZE + ssa_field_offset;
  libtea_read_enclave_addr(instance, ssa_field_addr, &ret, 8);

  return ret;
}

/* End libtea_enclave.c */
//---------------------------------------------------------------------------
