/* See LICENSE file for license and copyright information */

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea.h"
#include "Enclave/encl_u.h"
#include <inttypes.h>

#define TARGET_CPU 2

int aep_calls_count = 0;
int faults_count = 0;
void* enclave_ptr;
libtea_enclave_info* enclave;
libtea_instance* instance;

void custom_aep_function(void) {
  libtea_gprsgx_state gprsgx;
  uint64_t erip = libtea_get_erip(instance, enclave) - (uint64_t) libtea_get_enclave_base(enclave);
  printf("Hello world from a libtea AEP function!\n");
  libtea_read_secure_addr(instance, libtea_get_gprsgx_address(instance, enclave), &gprsgx, sizeof(libtea_gprsgx_state));
  uint64_t xsave_first_val = libtea_read_ssa_at_offset(instance, enclave, 0);
  printf("First uint64_t value in XSAVE region of SSA frame is %d\n", xsave_first_val);
  libtea_print_gprsgx_state(&gprsgx);
  aep_calls_count++;
}

void segfault_handler(int signum) {
  libtea_info("Caught SIGSEGV - enclave has been interrupted successfully. Restoring enclave access rights...");
  if(mprotect(enclave_ptr, 4096, PROT_READ|PROT_WRITE)) {
    libtea_info("mprotect failed");
  }
  faults_count++;
}

int main(int argc, char **argv){

  instance = libtea_init();
  if(!instance){
    libtea_info("Libtea test init failed.");
    return 1;
  }
  libtea_pin_to_core(getpid(), TARGET_CPU);

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 1: initializing the enclave, making a dummy call, and obtaining enclave info.");

  sgx_launch_token_t launch_token = {0};
  sgx_enclave_id_t enclave_id = 0;
  int retval = 0;
  int updated = 0;
  int created = sgx_create_enclave("./Enclave/encl.so", 1, &launch_token, &updated, &enclave_id, NULL);
  if(created != SGX_SUCCESS){
    libtea_info("Test 1 failed: could not create enclave, sgx_create_enclave returned value %d.\nThe enclave path is relative, so make sure you're running this directly in the tests/enclave folder.", created);
    goto libtea_test_enclave_cleanup;
  }
  libtea_info("Making dummy call to enclave to check it has launched...");
  enclave_dummy_call(enclave_id, &retval);
  libtea_info("Return value from dummy call was %d", retval);

  enclave = malloc(sizeof(libtea_enclave_info));
  libtea_init_enclave_info(instance, enclave);
  void* enclave_base = libtea_get_enclave_base(enclave);
  int enclave_size = libtea_get_enclave_size(enclave);
  libtea_info("Enclave base: %p", enclave_base);
  libtea_info("Enclave size: %d", enclave_size);
  libtea_info("Full enclave info:");
  libtea_print_enclave_info(instance, enclave);
  libtea_info("Test 1 passed.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 2: reading and writing enclave memory.");

  libtea_info("Testing reading and writing enclave memory...");
  get_a_addr(enclave_id, &enclave_ptr);
  libtea_info("Got an enclave pointer: %p", enclave_ptr);
  char old_val = 0;
  char new_val = 0xbb;
  libtea_read_secure_addr(instance, enclave_ptr, &old_val, 1);
  libtea_write_secure_addr(instance, enclave_ptr, &new_val, 1);
  libtea_read_secure_addr(instance, enclave_ptr, &new_val, 1);
  libtea_info("Read initial value: 0x%x, wrote 0xbb, read back 0x%x", old_val & 0xff, new_val & 0xff);
  if( (new_val & 0xff) != 0xbb){
    libtea_info("Test 2 failed: value read back was not the value we tried to write.");
    goto libtea_test_enclave_cleanup;
  }
  libtea_info("Test 2 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 3: interrupting enclave execution to call our custom AEP function");
  libtea_register_custom_aep_function(custom_aep_function);
  libtea_page_entry entry = libtea_resolve_addr(instance, enclave_ptr, 0);

  libtea_info("Revoking access rights to enclave address to cause a page fault during execution...");
  if(mprotect(enclave_ptr, 4096, PROT_NONE)){
    libtea_info("Test 3 failed: could not revoke access rights to enclave_ptr with mprotect");
    goto libtea_test_enclave_cleanup;
  }
  libtea_info("Access should now be revoked (PROT_NONE):");
  if(signal(SIGSEGV, segfault_handler) == SIG_ERR){
    libtea_info("Test 3 failed: could not register signal handler");
    goto libtea_test_enclave_cleanup;
  }
  libtea_info("Calling enclave...");
  enclave_dummy_call(enclave_id, &retval);
  signal(SIGSEGV, SIG_DFL);
  if(!aep_calls_count){
    libtea_info("Test 3 failed: custom AEP trampoline was not triggered during enclave execution.");
    goto libtea_test_enclave_cleanup;
  }
  libtea_info("Test 3 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("All tests completed.");
  libtea_test_enclave_cleanup:
  if(enclave){
    free(enclave);
  }
  libtea_info("Cleaning up...");
  sgx_destroy_enclave(enclave_id);
  libtea_cleanup(instance);
  libtea_info("Done!");
  return 0;
}


#ifdef __cplusplus
}
#endif
