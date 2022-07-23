/* See LICENSE file for license and copyright information */

#include "scfirefox.h"
#include "jsapi.h"
#include "libtea.h"
#include "vm/Interpreter-inl.h"

#define malloc(x) js_malloc(x)
#define free(x) js_free(x)

using namespace js;

libtea_instance* scfirefox_instance;
libtea_eviction_set scfirefox_set;

#define SCFIREFOX_MAX_FILE_COUNT 50
HANDLE scfirefox_fileViews[SCFIREFOX_MAX_FILE_COUNT];             /* Mapped address (Linux) or address of mapped view (Windows) */
libtea_file scfirefox_windowsMappings[SCFIREFOX_MAX_FILE_COUNT];  /* File mappings (used on Windows only) */
libtea_file scfirefox_fileHandles[SCFIREFOX_MAX_FILE_COUNT];      /* File descriptors (Linux) or handles (Windows) */
size_t scfirefox_fileSizes[SCFIREFOX_MAX_FILE_COUNT];
int scfirefox_fileCount = 0;

HANDLE scfirefox_sharedMem = NULL;
int scfirefox_sharedMemSize = 0;
#if LIBTEA_LINUX
libtea_file scfirefox_sharedMemHandle = 0;
#else
libtea_file scfirefox_sharedMemHandle = NULL;
PVOID windowsExceptionHandler = NULL;
#endif


/* Memory mapping protection flags
 * ===============================
 */ 
static bool scfirefox_get_define_prot_read(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  #if LIBTEA_LINUX
  args.rval().set(JS::NumberValue(PROT_READ)); 
  #else
  args.rval().set(JS::NumberValue(FILE_MAP_READ)); 
  #endif	  
  return true;
}

//Note: on Windows FILE_MAP_WRITE grants read AND write permissions - not possible to map write-only
static bool scfirefox_get_define_prot_write(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  #if LIBTEA_LINUX
  args.rval().set(JS::NumberValue(PROT_WRITE));
  #else
  args.rval().set(JS::NumberValue(FILE_MAP_WRITE));
  #endif
  return true;
}

static bool scfirefox_get_define_prot_exec(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  #if LIBTEA_LINUX
  args.rval().set(JS::NumberValue(PROT_EXEC));
  #else
  args.rval().set(JS::NumberValue(FILE_MAP_EXECUTE));	  
  #endif
  return true;
}

static bool scfirefox_get_define_prot_none(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  #if LIBTEA_LINUX
  args.rval().set(JS::NumberValue(PROT_NONE));
  return true;
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: PROT_NONE is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;
  #endif
}


/**
 * Initializes SCFirefox and underlying Libtea scfirefox_instance; initializes and acquires kernel module.
 *
 * :return: True if successfully initalized, false otherwise
 */
static bool init(JSContext* cx, unsigned argc, Value* vp){
  scfirefox_instance = libtea_init();
  if(scfirefox_instance == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: Could not initialize Libtea instance (with kernel driver).");
    return false;
  }
  else return true;
}


/**
 * Initializes SCFirefox and underlying Libtea scfirefox_instance without the kernel module
 * (paging, interrupts, and enclave functionality will be disabled).
 *
 * :return: True if successfully initalized, false otherwise
 */
static bool init_nokernel(JSContext* cx, unsigned argc, Value* vp){
  scfirefox_instance = libtea_init_nokernel();
  if(scfirefox_instance == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: Could not initialize Libtea instance (without kernel driver).");
    return false;
  }
  else return true;
}


/**
 * Cleans up SCFirefox and underlying Libtea scfirefox_instance; (if necessary) releases kernel module.
 *
 */
static bool cleanup(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  libtea_cleanup(scfirefox_instance);
  return true;
}


/**
 * Returns the virtual address of the JavaScript variable.
 * 
 * Note: You *must* use this function and pass the address returned when using other
 * SCFirefox functions, e.g. access(), rather than directly passing the JavaScript
 * variable, or SCFirefox will segfault.
 *
 * :param var: The JavaScript variable to determine the virtual address of
 * :return: The virtual address of var, or -1 if an error occurred
 */
static bool get_virtual_address(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_virtual_address takes 1 argument (var).");
    return false;
  }

  if(!args[0].isObject()){
    //TODO this returns a valid vaddr we can access, but it is *not* the vaddr of the var itself as reported by JS Shell debug functions - unclear how to get the vaddr for primitives
    //check API at js/public/experimental/TypedData.h for alternative functions here
    args.rval().set(JS::NumberValue((uint64_t) args[0].address()));
    return true;
  }

  RootedObject obj(cx, &args[0].toObject());
  size_t bufferLength = 0;
  bool isSharedMem = false;

  /* We return the address of the buffer data, i.e. we get the underlying ArrayBuffer for the view and then
   * we get the address in its DATA_SLOT (slot 0). Really important we use this address to flush/access array
   * values rather than the addresses of the objects.
   */
  if(JS_IsArrayBufferViewObject(obj)){
    uint8_t* bufferData = NULL;
    JS_GetObjectAsArrayBufferView(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));  /* Gets implicitly converted to a double, so we don't lose precision here */
    return true;
  }
  else if(JS_IsInt8Array(obj)){
    int8_t* bufferData = NULL;
    JS_GetObjectAsInt8Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsUint8Array(obj)){
    uint8_t* bufferData = NULL;
    JS_GetObjectAsUint8Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsUint8ClampedArray(obj)){
    uint8_t* bufferData = NULL;
    JS_GetObjectAsUint8ClampedArray(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsInt16Array(obj)){
    int16_t* bufferData = NULL;
    JS_GetObjectAsInt16Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsUint16Array(obj)){
    uint16_t* bufferData = NULL;
    JS_GetObjectAsUint16Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr)); 
    return true;
  }
  else if(JS_IsInt32Array(obj)){
    int32_t* bufferData = NULL;
    JS_GetObjectAsInt32Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsUint32Array(obj)){
    uint32_t* bufferData = NULL;
    JS_GetObjectAsUint32Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsFloat32Array(obj)){
    float* bufferData = NULL;
    JS_GetObjectAsFloat32Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else if(JS_IsFloat64Array(obj)){  
    double* bufferData = NULL;
    JS_GetObjectAsFloat64Array(obj, &bufferLength, &isSharedMem, &bufferData);
    uint64_t bufferDataAddr = (uint64_t) bufferData;
    args.rval().set(JS::NumberValue(bufferDataAddr));
    return true;
  }
  else{
    JS_ReportErrorUTF8(cx, "SCFirefox error: unrecognized array type.");
    args.rval().set(JS::NumberValue((uint64_t) args[0].address()));
    return true;
  }
}


/**
 * Accesses the provided address.
 *
 * :param addr: The virtual address
 */
static bool access(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_access((void*)addr);
  return true;
}


/**
 * Accesses the provided address (with memory barriers).
 *
 * :param addr: The virtual address
 */
static bool access_b(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_access_b((void*)addr);
  return true;
}


/**
 * Accesses the provided address within a try/catch block to suppress exceptions.
 *
 * :param addr: The virtual address
 */
static bool access_illegal(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_try_start(){
    libtea_access((void*)addr);
  }
  libtea_try_end();
  return true;
}


/**
 * Accesses the provided address (with memory barriers) within a try/catch block to suppress exceptions.
 *
 * :param addr: The virtual address
 */
static bool access_b_illegal(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_try_start(){
    libtea_access_b((void*)addr);
  }
  libtea_try_end();
  return true;
}


/**
 * Accesses the provided address speculatively. Success will vary depending on the microarchitecture
 * used (exact branch prediction implementation, ROB size etc). Tested to work on an Intel i7-8700K.
 *
 * :param addr: The virtual address
 */
static bool access_speculative(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_access_speculative((void*)addr);
  return true;
}


/**
 * Prefetches the provided address into the cache.
 *
 * :param addr: The virtual address
 */
static bool prefetch(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_prefetch((void*)addr);
  return true;	
}	


/**
 * Prefetches the provided address into the cache using an architecture-specific instruction (e.g. prefetchw) indicating that the CPU should anticipate a write to the address.
 *
 * :param addr: The virtual address
 */
static bool prefetch_anticipate_write(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_prefetch_anticipate_write((void*)addr);
  return true;	
}	


/**
 * Flushes the provided address from the cache.
 *
 * :param addr: The virtual address
 */
static bool flush(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_flush((void*)addr);
  return true;
}


/**
 * Flushes the provided address from the cache (with memory barriers).
 *
 * :param addr: The virtual address
 */
static bool flush_b(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_flush_b((void*)addr);
  return true;
}


/**
 * Begins a memory barrier (note that on x86, ending the barrier is unnecessary).
 *
 */
static bool barrier_start(JSContext* cx, unsigned argc, Value* vp){
  libtea_barrier_start();
  return true;
}


/**
 * Ends a memory barrier.
 *
 */
static bool barrier_end(JSContext* cx, unsigned argc, Value* vp){
  libtea_barrier_end();
  return true;
}


/**
 * Inserts a speculation barrier.
 *
 */
static bool speculation_barrier(JSContext* cx, unsigned argc, Value* vp){
  libtea_speculation_barrier();
  return true;
}


/**
 * Returns the current timestamp.
 *
 * :return: The current timestamp
 */
static bool timestamp(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t time = libtea_timestamp(scfirefox_instance);
  args.rval().set(JS::NumberValue(time));
  return true;
}


/**
 * Begin a timing measurement
 *
 */
static bool measure_start(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_measure_start(scfirefox_instance);
  return true;
}


/**
 * End a timing measurement
 *
 * :return: The time that has passed since the start of the measurement
 */
static bool measure_end(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t time = libtea_measure_end(scfirefox_instance);
  args.rval().set(JS::NumberValue(time));
  return true;
}


/**
 * Set the used timer. 
 * 
 * Note: on most systems you will need to run as root to use the perf timer.
 * Otherwise it will fail silently (returning 0).
 *
 * :param timer: A number representing the timer to use (0 == native timer, 1 == native AMD Zen2, 2 == native AMD Zen, 3 == counting thread, 4 == perf, 5 == monotonic clock)
 */
static bool set_timer(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  } 

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: set_timer takes 1 argument (timer).");
   return false;
  }

  int timer;
  JS::ToInt32(cx, args.get(0), &timer);
  libtea_set_timer(scfirefox_instance, (libtea_timer)timer);

  return true;
}


/**
 * Runs the provided function (without arguments) in a specpoline block so that it will only
 * be executed transiently.
 *
 * :param funcName: The function name
 */
static bool specpoline(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  
  #if LIBTEA_INLINEASM
  JS::PersistentRootedString nameArg(cx);
  nameArg = args.get(0).toString(); 
  JS::UniqueChars funcName = JS_EncodeStringToUTF8(cx, nameArg);
  JS::PersistentRootedValue r(cx);
  JS::PersistentRootedObject globalObj(cx, JS::CurrentGlobalOrNull(cx));

  libtea_speculation_start(specpoline);
    JS_CallFunctionName(cx, globalObj, funcName.get(), JS::HandleValueArray::empty(), &r);
  libtea_speculation_end(specpoline);
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: specpoline requires compiler support for inline assembly (LIBTEA_INLINEASM).");
  return false;
  #endif  
}


/**
 * Gets the current CPU core.
 *
 * :return: The ID of the core
 */
static bool get_current_core(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
 
  #if LIBTEA_LINUX
  int core = sched_getcpu();
  #else
  int core = GetCurrentProcessorNumber();
  #endif

  args.rval().set(JS::NumberValue(core));
  return true;
}


/**
 * Gets the ID of the sibling hyperthread of the provided core (Linux-only).
 *
 * :param logical_core: The logical core
 * :return: The ID of the sibling hyperthread
 */
static bool get_hyperthread(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: get_hyperthread takes 1 argument (logical core).");
   return false;
  }

  int core;
  JS::ToInt32(cx, args.get(0), &core);
  int hyperthread = libtea_get_hyperthread(core);

  args.rval().set(JS::NumberValue(hyperthread));
  return true;
}


/**
 * Pins the current process to the provided core.
 *
 * :param core: The core the process should be pinned to
 */
static bool pin_to_core(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: pin_to_core takes 1 argument (core).");
   return false;
  }
  
  int core;
  JS::ToInt32(cx, args.get(0), &core);

  libtea_thread process;
  #if LIBTEA_LINUX
  process = getpid();
  #else
  process = GetCurrentProcess();
  #endif

  libtea_pin_to_core(process, core);
  return true;
}


/**
 * Returns the process ID of the JS shell / current Firefox tab.
 *
 * :param pid: The current process ID
 */
static bool get_current_process_id(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);

  int pid;
  #if LIBTEA_LINUX
  pid = getpid();
  #else
  pid = GetCurrentProcessId();
  #endif

  args.rval().set(JS::NumberValue(pid));
  return true;
}


/**
 * Returns the physical address of the provided virtual address.
 * 
 * Note: this function must be run with root privileges.
 *
 * :param vaddr: The virtual address
 * :return: The corresponding physical address
 */
static bool get_physical_address(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address takes 1 argument (vaddr).");
   return false;
  }

  uint64_t vaddr;
  JS::ToUint64(cx, args.get(0), &vaddr);
  size_t paddr = libtea_get_physical_address(scfirefox_instance, (size_t)vaddr);
  if((int)paddr == LIBTEA_ERROR){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address failed. Are you running with root privileges?.");
    return false;
  }

  args.rval().set(JS::NumberValue(paddr));
  return true;
}


/**
 * Returns the physical address of the provided ArrayBufferView object.
 * 
 * Note: this function must be run with root privileges.
 *
 * :param obj: The JavaScript object
 * :return: The corresponding physical addres
 */
static bool get_physical_address_obj(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address_obj takes 1 argument (obj).");
   return false;
  }
  get_virtual_address(cx, argc, vp);
  args = CallArgsFromVp(argc, vp);

  uint64_t vaddr;
  JS::ToUint64(cx, args.rval(), &vaddr);
  size_t paddr = libtea_get_physical_address(scfirefox_instance, (size_t)vaddr);
  if((int)paddr == LIBTEA_ERROR){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address failed. Are you running with root privileges?.");
    return false;
  }

  args.rval().set(JS::NumberValue(paddr));
  return true;
}


/**
 * Opens a shared memory region.
 *
 * Note: SCFirefox only supports one shared memory region being open at 
 * a time. You must close the shared memory when you finish using it using
 * close_shared_memory().
 *
 * :param size: Desired size of the region in bytes
 *
 * :return: The virtual address of the shared memory.
 */
static bool open_shared_memory(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: open_shared_memory takes 1 argument (size).");
   return false;
  }

  int size;
  JS::ToInt32(cx, args.get(0), &size);

  if(scfirefox_sharedMem){
    JS_ReportErrorUTF8(cx, "SCFirefox error: open_shared_memory failed. Only one shared memory region can be open in SCFirefox at a time.");
    return false;
  }

  /* Note: scfirefox_sharedMem is a handle to a mapped view of the shared memory. To map additional views
   * of the shared memory, we need to use scfirefox_sharedMemHandle. We auto-convert to handle this case
   * (and others!) in map().
   */
  scfirefox_sharedMem = libtea_open_shared_memory(size, &scfirefox_sharedMemHandle);
  if(scfirefox_sharedMem == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: open_shared_memory failed to create a shared memory region.");
    return false;
  }
  memset(scfirefox_sharedMem, 1, 4096);

  scfirefox_sharedMemSize = size;
  args.rval().set(JS::NumberValue((uint64_t)scfirefox_sharedMem));
  return true;
}


/**
 * Closes a shared memory region created with open_shared_memory.
 *
 * Note: SCFirefox only supports one shared memory region being open at
 * a time.
 */
static bool close_shared_memory(JSContext* cx, unsigned argc, Value* vp){

  int ret = libtea_close_shared_memory(scfirefox_sharedMem, &scfirefox_sharedMemHandle, scfirefox_sharedMemSize);
  if(ret == LIBTEA_ERROR){
    JS_ReportErrorUTF8(cx, "SCFirefox error: close_shared_memory could not close the shared memory region.");
    return false;
  }
  scfirefox_sharedMem = NULL;
  #if LIBTEA_LINUX
  scfirefox_sharedMemHandle = 0;
  #else
  scfirefox_sharedMemHandle = NULL;
  #endif
  scfirefox_sharedMemSize = 0;

  return true;
}


/**
 * Starts a leaky thread.
 *
 * :param type: The type of leaky thread to create. 1 for load loop, 2 for store loop, 3 for nop loop.
 * :param secret: A byte value to repeatedly load/store (ignored for nop loop, but you must still provide a value).
 * :param shared: 1 to use the SCFirefox shared memory region, 0 otherwise.
 * :param core: The CPU core to lock the thread to.
 */
static bool start_leaky_thread(JSContext* cx, unsigned argc, Value* vp) {

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  } 

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 4) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: start_leaky_thread takes 4 arguments (type, secret, shared, core).");
    return false;
  }

  int type, secret, shared, core;
  JS::ToInt32(cx, args.get(0), &type);
  JS::ToInt32(cx, args.get(1), &secret);
  JS::ToInt32(cx, args.get(2), &shared);
  JS::ToInt32(cx, args.get(3), &core);

  libtea_thread thread;
  if(shared){
    thread = libtea_start_leaky_thread(scfirefox_instance, type, (unsigned char) secret, scfirefox_sharedMem, core);
  }
  else{
    thread = libtea_start_leaky_thread(scfirefox_instance, type, (unsigned char) secret, NULL, core);
  }

  return true;
}


/**
 * Stops the victim thread initialized with start_leaky_thread().
 */
static bool stop_leaky_thread(JSContext* cx, unsigned argc, Value* vp) {

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  } 

  libtea_stop_leaky_thread(scfirefox_instance);
  return true;
}


/**
 * Creates a new mapping to an existing memory-mapped region.
 * 
 * Note: You should unmap the allocated region with scfirefox_munmap().
 * On Windows, the mapping parameter (return argument from SCFirefox functions,
 * i.e. the file view handle) will be *automatically* converted to the underlying
 * file mapping handle to provide identical behavior to Linux.
 *
 * :param address: Address of the existing memory-mapped region
 * :param size: The size of the mapping 
 * :param prot: Protection flags to apply (e.g. SCFirefox.PROT_READ)
 * :return: Mapped address
 */
static bool map(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: map takes 3 arguments (address, size, rw).");
    return false;
  }
  
  if(scfirefox_fileCount >= (SCFIREFOX_MAX_FILE_COUNT-1)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: max supported number of files/regions memory-mapped!");
    return false;
  }

  uint64_t mem_arg = 0;
  JS::ToUint64(cx, args.get(0), &mem_arg);
  int buffer_size = 0;
  JS::ToInt32(cx, args.get(1), &buffer_size);
  int prot = 0;
  JS::ToInt32(cx, args.get(2), &prot);

  HANDLE mem = (HANDLE)mem_arg;
  HANDLE map;

  #if LIBTEA_LINUX
  map = mmap(mem, buffer_size, prot, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
  if (map == MAP_FAILED){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map failed to create a mapping.");
    return false;
  }

  #else
  /* Windows conversion from file view handle to file mapping handle */
  bool found = false;
  /* First check if user passed in scfirefox_sharedMem, which we store separately from other files */
  if(mem == scfirefox_sharedMem){
    mem = scfirefox_sharedMemHandle;
    found = true;
  }
  else{
    /* Search through file list */
    for(int i=0; i<scfirefox_fileCount; i++){
      if(mem == scfirefox_fileViews[i]){
        mem = scfirefox_windowsMappings[i];
        found = true;
        break;
      }
    }
  }
  if(!found){
    JS_ReportErrorUTF8(cx, "SCFirefox error: could not auto-convert file view handle to file mapping handle!");
    return false;
  }

  map = MapViewOfFile(mem, prot, 0, 0, buffer_size);
  if(map == NULL) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: map failed to create a mapping, last error is %ul.", GetLastError());
    return false;
  }
  #endif

  args.rval().set(JS::NumberValue((uint64_t)map));
  return true;
}


/**
 * Maps a page of the given file at the defined offset to the program's
 * address space and returns its address. Linux only.
 *
 * Note: You must keep track of the order in which you open files and
 * unmap them when finished using scfirefox_munmap_file().
 *
 * :param filename: The path to the file
 * :param rw: 0 for a read-only mapping, 1 for write-only, 2 for read-write
 * :param offset: The offset that should be mounted
 *
 * :return: The address of the mapped page
 */
static bool map_file_by_offset(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX
  if (args.length() != 3 || !args.get(0).isString()) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file_by_offset takes 3 arguments (filename, rw, offset).");
    return false;
  }

  if(scfirefox_fileCount >= (SCFIREFOX_MAX_FILE_COUNT-1)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: max supported number of files mapped!");
    return false;
  }

  int len = args.get(0).toString()->length();
  char* filename = (char*) JS_malloc(cx, len*sizeof(char));
  if(!JS_EncodeStringToBuffer(cx, args.get(0).toString(), filename, len)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file_by_offset filename string conversion failed!");
    return false;
  }

  int rw = 0;
  JS::ToInt32(cx, args.get(1), &rw);
  uint64_t offset;
  JS::ToUint64(cx, args.get(2), &offset);
  void* addr = libtea_map_file_by_offset(filename, &scfirefox_fileSizes[scfirefox_fileCount], &scfirefox_fileHandles[scfirefox_fileCount], rw, offset);
  scfirefox_fileViews[scfirefox_fileCount] = addr;
  scfirefox_fileCount++;
  JS_free(cx, (void*)filename);

  if(addr == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file_by_offset failed to map file!");
    scfirefox_fileCount--;
    return false;
  }

  args.rval().set(JS::NumberValue((uint64_t)addr));
  return true;

  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: map_file_by_offset is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;
  #endif
}


/**
 * Maps an entire file to the program's address space and returns its address.
 *
 * Note: You must keep track of the order in which you open files and 
 * unmap them when finished using scfirefox_munmap_file().
 *
 * :param filename: The path to the file
 * :param rw: 0 for a read-only mapping, 1 for write-only, 2 for read-write
 * :return: The address of the mapped file
 */
static bool map_file(JSContext* cx, unsigned argc, Value* vp){
    
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2 || !args.get(0).isString()) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file takes 2 arguments (filename, rw).");
    return false;
  }
  
  if(scfirefox_fileCount >= (SCFIREFOX_MAX_FILE_COUNT-1)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: max supported number of files mapped!");
    return false;
  }

  int len = args.get(0).toString()->length();
  char* filename = (char*) JS_malloc(cx, len*sizeof(char));
  if(!JS_EncodeStringToBuffer(cx, args.get(0).toString(), filename, len)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file filename string conversion failed!");
    return false;
  }
  int rw = 0;
  JS::ToInt32(cx, args.get(1), &rw);

  void* addr = libtea_map_file(filename, &scfirefox_fileSizes[scfirefox_fileCount], &scfirefox_fileHandles[scfirefox_fileCount], &scfirefox_windowsMappings[scfirefox_fileCount], rw);
  scfirefox_fileViews[scfirefox_fileCount] = addr;
  scfirefox_fileCount++;
  JS_free(cx, (void*)filename);

  if(addr == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_file failed to map file!");
    scfirefox_fileCount--;
    return false;
  }

  args.rval().set(JS::NumberValue((uint64_t)addr));
  return true;
}


/**
 * Unmaps a file mapped with SCFirefox.
 *
 * :param index: Index of the file based on the order you mapped files in. E.g. for 1st file mapped: 0, 2nd: 1, etc.
 */
static bool munmap_file(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: munmap_file takes 1 argument (index).");
    return false;
  }

  int index;
  JS::ToInt32(cx, args.get(0), &index);

  int ret = libtea_munmap_file(scfirefox_fileViews[index], scfirefox_fileSizes[index], &scfirefox_fileHandles[index], &scfirefox_windowsMappings[index]);
  if(ret != LIBTEA_SUCCESS){
    JS_ReportErrorUTF8(cx, "SCFirefox error: munmap_file failed!");
    return false;
  }

  scfirefox_fileCount--;
  return true;
}


/**
 * Finds the index of the nth largest number in the list (size_t used for conversion)
 *
 * :param list: The list
 * :param nmemb: Number of list entries
 * :param n: Value of n (0 == largest)
 * :return: The index
 */
static bool find_index_of_nth_largest_num(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3 || !args.get(0).isObject()) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: find_index_of_nth_largest_num takes 3 arguments (list, nmemb, n).");
    return false;
  }

  JS::HandleValueArray js_array = JS::HandleValueArray(args.get(0));
  int nmemb, n;
  JS::ToInt32(cx, args.get(1), &nmemb);
  JS::ToInt32(cx, args.get(2), &n);
  if(nmemb < 1 || n > nmemb || nmemb != (int)js_array.length()){
    JS_ReportErrorUTF8(cx, "SCFirefox error: find_index_of_nth_largest_num had invalid arguments. Check that list is an array, nmemb > 0, and n < nmemb.");
    return false;
  }

  size_t* list = (size_t*) JS_malloc(cx, nmemb*sizeof(size_t));
  for(int i=0; i<nmemb; i++){
    uint64_t temp;
    JS::ToUint64(cx, js_array.operator[](i), &temp);
    list[i] = (size_t)temp;
  }

  int index = libtea_find_index_of_nth_largest_sizet(list, nmemb, n);

  JS_free(cx, list);
  args.rval().set(JS::NumberValue(index));
  return true;
}


/**
 * Writes to a model-specific register (MSR) / system register.
 *
 * :param cpu: The core id
 * :param reg: The register
 * :param val: The value
 */
static bool write_system_reg(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  } 

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: write_system_reg takes 3 arguments (cpu, reg, val).");
    return false;
  }

  int cpu;
  JS::ToInt32(cx, args.get(0), &cpu);
  uint32_t reg;
  JS::ToUint32(cx, args.get(1), &reg);
  uint64_t val;
  JS::ToUint64(cx, args.get(2), &val);

  int ret = libtea_write_system_reg(scfirefox_instance, cpu, reg, val);
  if (ret == LIBTEA_ERROR) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: write_system_reg failed to write to the provided register.");
    return false;
  }

  return true;
}


/**
 * Reads from a model-specific register (MSR) / system register.
 *
 * :param cpu: The core id
 * :param reg: The register
 * :return: The value of the register
 */
static bool read_system_reg(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2) {
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    JS_ReportErrorUTF8(cx, "SCFirefox error: read_system_reg takes 2 arguments (cpu, reg).");
    return false;
  }

  int cpu;
  JS::ToInt32(cx, args.get(0), &cpu);
  uint32_t reg;
  JS::ToUint32(cx, args.get(1), &reg);

  size_t reg_val = libtea_read_system_reg(scfirefox_instance, cpu, reg);
  if ((int)reg_val == LIBTEA_ERROR) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: read_system_reg failed to read the provided register.");
    return false;
  }
  
  args.rval().set(JS::NumberValue((uint64_t)reg_val));
  return true;
}


/**
 * Disables all hardware prefetchers (supported on Intel only)
 *
 */
static bool disable_hardware_prefetchers(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_disable_hardware_prefetchers(scfirefox_instance);
  return true;
}


/**
 * Enables all hardware prefetchers (supported on Intel only)
 *
 */
static bool enable_hardware_prefetchers(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_enable_hardware_prefetchers(scfirefox_instance);
  return true;
}


/**
 * Disables Turbo Boost and sets the CPU minimum and maximum P-states to the provided integer percentage of
 * available performance to improve reproducibility of attack and benchmark results. Supported for Intel CPUs
 * on Linux only.
 *
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool set_cpu_pstate(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 1) {
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_cpu_pstate takes 1 argument (perf_percentage).");
    return false;
  }

  int perf_percentage;
  JS::ToInt32(cx, args.get(0), &perf_percentage);

  int ret = libtea_set_cpu_pstate(scfirefox_instance, perf_percentage);
  args.rval().set(JS::NumberValue(ret));
  return true;
}


/**
 * Restores the CPU minimum and maximum P-states and Turbo Boost setting to their original values prior to the
 * last call to set_cpu_pstate. Supported for Intel CPUs on Linux only.
 *
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool restore_cpu_pstate(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  int ret = libtea_restore_cpu_pstate(scfirefox_instance);
  args.rval().set(JS::NumberValue(ret));
  return true;
}


/**
 * Enables use of malloc in Javascript.
 *
 * :param bytes: Number of bytes to allocate
 * :return: The address of the allocated memory
 */
static bool scfirefox_malloc(JSContext* cx, unsigned argc, Value* vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 ) {
      JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_malloc takes 1 parameter (bytes).");
      return false;
    }

    uint64_t bytes;
    JS::ToUint64(cx, args.get(0), &bytes);

    void* ptr = JS_malloc(cx, bytes);
    if (ptr == NULL) {
      JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_malloc allocation failed!");
      return false;
    }
    memset(ptr, 0, bytes);
    
    args.rval().set(JS::NumberValue((uint64_t)ptr));
    return true;
};


/**
 * Enables use of free in Javascript.
 * 
 * :param addr: Address to free
 */
static bool scfirefox_free(JSContext* cx, unsigned argc, Value* vp){
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 ) {
      JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_free takes 1 parameter (addr).");
      return false;
    }

    uint64_t ptr;
    JS::ToUint64(cx, args.get(0), &ptr);
    JS_free(cx, (void*)ptr);
    return true;
};


/**
 * Creates a new memory mapping.
 * 
 * Note: you should unmap the allocated region with scfirefox_munmap().
 *
 * :param buffer_size: The size of the region to map 
 * :param rw: 0 for a read-only mapping, 1 for write-only (Linux-only), 2 for read-write
 * :return: The address of the new mapping
 */
static bool scfirefox_mmap(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_mmap takes 2 arguments (buffer_size, rw).");
    return false;
  }
  
  if(scfirefox_fileCount >= (SCFIREFOX_MAX_FILE_COUNT-1)){
    JS_ReportErrorUTF8(cx, "SCFirefox error: max supported number of files/regions memory-mapped!");
    return false;
  }

  int buffer_size = 0;
  JS::ToInt32(cx, args.get(0), &buffer_size);
  int rw = 0;
  JS::ToInt32(cx, args.get(1), &rw);

  void* addr = libtea_mmap(buffer_size, &scfirefox_windowsMappings[scfirefox_fileCount], rw);
  scfirefox_fileViews[scfirefox_fileCount] = addr;
  scfirefox_fileSizes[scfirefox_fileCount] = buffer_size;
  scfirefox_fileCount++;

  if(addr == NULL){
    JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_mmap failed to map the region!");
    scfirefox_fileCount--;
    return false;
  }

  args.rval().set(JS::NumberValue((uint64_t)addr));
  return true;
}


/**
 * Unmaps a memory mapping created with SCFirefox.
 *
 * :param index: Index of the region based on the order you mapped files/regions in. E.g. for 1st mapped: 0, 2nd: 1, etc.
 */
static bool scfirefox_munmap(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_munmap takes 1 argument (index).");
    return false;
  }

  int index;
  JS::ToInt32(cx, args.get(0), &index);

  int ret = libtea_munmap(scfirefox_fileViews[index], scfirefox_fileSizes[index], &scfirefox_windowsMappings[index]);
  if(ret != LIBTEA_SUCCESS){
    JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_munmap failed!");
    return false;
  }

  scfirefox_fileCount--;
  return true;  
}


/**
 * Enables use of memset in Javascript, e.g. to initialize mapped memory
 * regions.
 * 
 * :param addr: Address of the memory region
 * :param value: Integer value to set the memory region to
 * :param size: Number of bytes to set
 */
static bool scfirefox_memset(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: scfirefox_memset takes 3 arguments (addr, value, size).");
    return false;
  }

  uint64_t addr;
  int value;
  uint64_t bytes;
  JS::ToUint64(cx, args.get(0), &addr);
  JS::ToInt32(cx, args.get(1), &value);
  JS::ToUint64(cx, args.get(2), &bytes);

  memset((void*)addr, value, (size_t)bytes);  
  return true;
}


/**
 * Enables use of sched_yield (or SwitchToThread on Windows) in Javascript. 
 * Typical usage: briefly suspend an attacker process to allow a victim event
 * to occur.
 */
static bool scfirefox_sched_yield(JSContext* cx, unsigned argc, Value* vp){
  #if LIBTEA_LINUX
  sched_yield();
  #else
  SwitchToThread();
  #endif
  return true;
}


/**
 * Returns the address of the SCFirefox instance.
 * 
 * :return: Virtual address of the SCFirefox instance.
 */
static bool get_instance(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((uint64_t)scfirefox_instance));
  return true;
}


/* Cache functionality
 * ===================
 */


/**
 * Returns the current Libtea LLC cache miss threshold value.
 * 
 * :return: The LLC cache miss threshold value
 */
static bool get_threshold(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(scfirefox_instance->llc_miss_threshold));
  return true;
}


/**
 * Sets the current Libtea LLC cache miss threshold value.
 * 
 * :param threshold: The new LLC cache miss threshold value
 */
static bool set_threshold(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  int threshold;
  JS::ToInt32(cx, args.get(0), &threshold);
  scfirefox_instance->llc_miss_threshold = threshold;

  return true;
}


/**
 * Performs Flush+Reload on the provided address and returns hit/miss based on 
 * the current threshold.
 *
 * :param addr: The address
 * :return: 1 if the address was in the cache, 0 if the address was not cached
 */
static bool flush_reload(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: flush_reload takes 1 argument (vaddr).");
   return false;
  }

  uint64_t vaddr;
  JS::ToUint64(cx, args.get(0), &vaddr);
  int cached = libtea_flush_reload(scfirefox_instance, (void*)vaddr);

  args.rval().set(JS::NumberValue(cached));
  return true;
}


/**
 * Performs Flush+Reload on the provided address and returns the access time.
 * 
 * Note: as an optimization, uses no memory barriers between timing start/end
 * and access.
 *
 * :param addr: The address
 * :return: The access time
 */
static bool flush_reload_time(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t vaddr;
  JS::ToUint64(cx, args.get(0), &vaddr);
  libtea_measure_start(scfirefox_instance);  
  libtea_access((void*)vaddr); 
  uint64_t time = libtea_measure_end(scfirefox_instance);
  libtea_flush((void*)vaddr);

  args.rval().set(JS::NumberValue(time));
  return true;
}


/**
 * Calibrates the threshold to distinguish between a cache hit and cache
 * miss using Flush+Reload.
 */
static bool calibrate_flush_reload(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_calibrate_flush_reload(scfirefox_instance);
  return true;
}


/**
 * Flush all pages of the SCFirefox cache covert channel from the cache.
 */
static bool flush_covert_channel(JSContext* cx, unsigned argc, Value* vp){
  for(int i=0; i < LIBTEA_COVERT_CHANNEL_ENTRIES; i++){
    libtea_flush((char*)scfirefox_instance->covert_channel + i * LIBTEA_COVERT_CHANNEL_OFFSET);
  }
  return true;
}


/**
 * Returns the cache slice of the provided physical address
 *
 * :param paddr: The physical address
 * :return: Cache slice of the physical address
 */
static bool get_cache_slice(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: get_cache_slice takes 1 argument (paddr).");
   return false;
  }

  uint64_t paddr;
  JS::ToUint64(cx, args.get(0), &paddr);
  int slice = libtea_get_cache_slice(scfirefox_instance, (size_t)paddr);

  args.rval().set(JS::NumberValue(slice));
  return true;
}


/**
 * Returns the cache set of the provided physical address
 *
 * :param paddr: The physical address
 * :return: Cache set of the physical address
 */
static bool get_cache_set(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: get_cache_set takes 1 argument (paddr).");
   return false;
  }

  uint64_t paddr;
  JS::ToUint64(cx, args.get(0), &paddr);
  int set = libtea_get_cache_set(scfirefox_instance, (size_t)paddr);

  args.rval().set(JS::NumberValue(set));
  return true;
}


/**
 * Builds an eviction set for the provided physical address. The resulting set is stored
 * internally in the SCFirefox instance; it is not returned.
 *
 * :param paddr: The physical address
 */
static bool build_eviction_set(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: build_eviction_set takes 1 argument (paddr).");
   return false;
  }

  uint64_t paddr;
  JS::ToUint64(cx, args.get(0), &paddr);
  int ret_val = libtea_build_eviction_set(scfirefox_instance, &scfirefox_set, (size_t)paddr);
  if(ret_val == LIBTEA_ERROR){
    JS_ReportErrorUTF8(cx, "SCFirefox error: build_eviction_set failed to build the set.");
    return false;
  }

  return true;
}


/**
 * Runs eviction using the last built eviction set
 *
 */
static bool evict(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_evict(scfirefox_instance, scfirefox_set);
  return true;
}


/**
 * Performs Evict+Reload using the last built eviction set
 * 
 * :param addr: The virtual address
 * :return: 1 if addr was cached
 */
static bool evict_reload(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: evict_reload takes 1 argument (addr).");
   return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  int cached = libtea_evict_reload(scfirefox_instance, (void*)addr, scfirefox_set);

  args.rval().set(JS::NumberValue(cached));
  return true;
}


/**
 * Calibrates the threshold to distinguish between a cache hit and cache
 * miss using Evict+Reload
 */
static bool calibrate_evict_reload(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  libtea_calibrate_evict_reload(scfirefox_instance);
  return true;
}


/**
 * Performs the prime step using the last built eviction set
 * 
 */
static bool prime(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_prime(scfirefox_instance, scfirefox_set);
  return true;
}


/**
 * Performs Prime+Probe using the last built eviction set.
 * 
 * :return: The execution time of the probe step
 */
static bool prime_probe(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  int time = libtea_prime_probe(scfirefox_instance, scfirefox_set);
  args.rval().set(JS::NumberValue(time));
  return true;
}


/**
 * Calculates the slice ID of the provided virtual address using performance counter measurement
 * (requires MSR access; Intel only).
 *
 * :param addr: The virtual address
 * :return: The slice ID
 */
static bool measure_slice(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: measure_slice takes 1 argument (addr).");
   return false;
  }

  uint64_t vaddr;
  JS::ToUint64(cx, args.get(0), &vaddr);
  int slice = libtea_measure_slice(scfirefox_instance, (void*)vaddr);

  args.rval().set(JS::NumberValue(slice));
  return true;
}


/**
 * Encodes a single ASCII character into the cache. The value should be passed as a number 0-255.
 *
 * :param value: The value to encode
 */
static bool cache_encode(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  unsigned char value;
  JS::ToUint8(cx, args.get(0), &value);
  libtea_cache_encode(scfirefox_instance, value);
  return true;
}


/**
 * Dereferences an address at the provided offset and encodes the dereferenced value into the cache.
 *
 * :param addr: The virtual address to dereference
 * :param offset: The offset to dereference at
 */
static bool cache_encode_dereference(JSContext* cx, unsigned argc, Value* vp){ 
  CallArgs args = CallArgsFromVp(argc, vp);
  uint64_t addr;
  int offset; 
  JS::ToUint64(cx, args.get(0), &addr);
  JS::ToInt32(cx, args.get(1), &offset);
  libtea_cache_encode_dereference(scfirefox_instance, (char*)addr, offset);
  return true;
}


/**
 * Decodes a value in the provided range from the cache
 *
 * :param from: Range begin (inclusive)
 * :param to: Range end (inclusive)
 * :param use_mix: Whether to check the LUT in a non-linear pattern to avoid hardware prefetching effects (pass as boolean). Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR if no cache hit occurred
 */
static bool cache_decode_from_to(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  int from, to;
  JS::ToInt32(cx, args.get(0), &from);
  JS::ToInt32(cx, args.get(1), &to);
  bool use_mix = JS::ToBoolean(args.get(2));
  int decoded = libtea_cache_decode_from_to(scfirefox_instance, from, to, use_mix);
  args.rval().setInt32(decoded);
  return true;
}


/**
 * Decodes a value from the cache.
 *
 * :param use_mix: Whether to check the LUT in a non-linear pattern to avoid hardware prefetching effects (pass as boolean). Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR if no cache hit occurred
 */
static bool cache_decode(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  bool use_mix = JS::ToBoolean(args.get(0));
  int decoded = libtea_cache_decode(scfirefox_instance, use_mix);
  args.rval().setInt32(decoded);
  return true;
}


/**
 * Decodes a value from the cache (no null version).
 *
 * :param use_mix: Whether to check the LUT in a non-linear pattern to avoid hardware prefetching effects (pass as boolean). Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR if no cache hit occurred
 */
static bool cache_decode_nonull(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  bool use_mix = JS::ToBoolean(args.get(0));
  int decoded = libtea_cache_decode_nonull(scfirefox_instance, use_mix);
  args.rval().setInt32(decoded);
  return true;
}


/**
 * Returns a histogram of decoded cache covert channel values over the provided number
 * of iterations as an int array.
 * 
 * Note: Libtea's optional activity function parameter for this function is not supported 
 * in SCFirefox.
 * 
 * :param iterations: The number of iterations to repeat for
 * :param sleep_len: The number of microseconds to sleep for between iterations (0 to not sleep)
 * :param yield: If true, call sched_yield() / SwitchToThread() between iterations
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :param offset: The value to add to the covert channel index to get the actual encoded character (if using <256 entries)
 * :param from: The index in the covert channel to start decoding from (inclusive)
 * :param to: The index in the covert channel to stop decoding at (inclusive)
 */
static bool numeric_cache_decode_histogram(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 5){
    JS_ReportErrorUTF8(cx, "SCFirefox error: numeric_cache_decode_histogram takes 5 arguments (iterations, sleep_len, flush, yield, use_mix).");
    return false;
  }

  int iterations, sleep_len, offset, from, to;
  JS::ToInt32(cx, args.get(0), &iterations);
  JS::ToInt32(cx, args.get(1), &sleep_len);
  bool yield = JS::ToBoolean(args.get(2));
  bool use_mix = JS::ToBoolean(args.get(3));
  JS::ToInt32(cx, args.get(4), &offset);
  JS::ToInt32(cx, args.get(5), &from);
  JS::ToInt32(cx, args.get(6), &to);

  int* hist = libtea_numeric_cache_decode_histogram(scfirefox_instance, iterations, sleep_len, yield, use_mix, NULL, offset, from, to);

  //TODO test further, not convinced this is the best way to do this
  JS::RootedObject hist_js = JS::RootedObject(cx, JS::NewArrayObject(cx, LIBTEA_COVERT_CHANNEL_ENTRIES));
  JS::MutableHandleObject hist_js_handle = &hist_js;
  for(int i=0; i < LIBTEA_COVERT_CHANNEL_ENTRIES; i++){
    JS_SetElement(cx, hist_js_handle, i, hist[i]);
  }
  args.rval().setObject(*hist_js);
  free(hist);
  return true;
}


/* Paging functionality
 * ====================
 */


/* Arch-specific paging definitions - Libtea enums are not exported to the browser console */


#if LIBTEA_X86

static bool scfirefox_get_define_page_bit_present(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PRESENT));
  return true;
}

static bool scfirefox_get_define_page_bit_rw(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_RW));
  return true;
}

static bool scfirefox_get_define_page_bit_user(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_USER));
  return true;
}

static bool scfirefox_get_define_page_bit_pwt(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PWT));
  return true;
}

static bool scfirefox_get_define_page_bit_pcd(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PCD));
  return true;
}

static bool scfirefox_get_define_page_bit_accessed(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_ACCESSED));
  return true;
}

static bool scfirefox_get_define_page_bit_dirty(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_DIRTY));
  return true;
}

static bool scfirefox_get_define_page_bit_pse(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PSE));
  return true;
}

static bool scfirefox_get_define_page_bit_pat(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PAT));
  return true;
}

static bool scfirefox_get_define_page_bit_global(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_GLOBAL));
  return true;
}

static bool scfirefox_get_define_page_bit_softw1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW1));
  return true;
}

static bool scfirefox_get_define_page_bit_softw2(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW2));
  return true;
}

static bool scfirefox_get_define_page_bit_softw3(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW3));
  return true;
}

static bool scfirefox_get_define_page_bit_pat_large(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PAT_LARGE));
  return true;
}

static bool scfirefox_get_define_page_bit_softw4(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW4));
  return true;
}

static bool scfirefox_get_define_page_bit_pkey_bit0(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PKEY_BIT0));
  return true;
}

static bool scfirefox_get_define_page_bit_pkey_bit1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PKEY_BIT1));
  return true;
}

static bool scfirefox_get_define_page_bit_pkey_bit2(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PKEY_BIT2));
  return true;
}

static bool scfirefox_get_define_page_bit_pkey_bit3(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PKEY_BIT3));
  return true;
}

static bool scfirefox_get_define_page_bit_nx(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_NX));
  return true;
}

static bool scfirefox_get_define_mt_bit_uc(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_UNCACHEABLE));
  return true;
}

static bool scfirefox_get_define_mt_bit_wc(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_COMBINING));
  return true;
}

static bool scfirefox_get_define_mt_bit_wt(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_THROUGH));
  return true;
}

static bool scfirefox_get_define_mt_bit_wp(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_PROTECTED));
  return true;
}

static bool scfirefox_get_define_mt_bit_wb(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_BACK));
  return true;
}

static bool scfirefox_get_define_mt_bit_ucminus(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_UNCACHEABLE_MINUS));
  return true;
}

#endif

#if LIBTEA_AARCH64

static bool scfirefox_get_define_page_bit_type_bit0(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_TYPE_BIT0));
  return true;
}

static bool scfirefox_get_define_page_bit_type_bit1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_TYPE_BIT1));
  return true;
}

static bool scfirefox_get_define_page_bit_mair_bit0(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_MAIR_BIT0));
  return true;
}

static bool scfirefox_get_define_page_bit_mair_bit1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_MAIR_BIT1));
  return true;
}

static bool scfirefox_get_define_page_bit_mair_bit2(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_MAIR_BIT2));
  return true;
}

static bool scfirefox_get_define_page_bit_non_secure(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_NON_SECURE));
  return true;
}

static bool scfirefox_get_define_page_bit_permission_bit0(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PERMISSION_BIT0));
  return true;
}

static bool scfirefox_get_define_page_bit_permission_bit1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PERMISSION_BIT1));
  return true;
}

static bool scfirefox_get_define_page_bit_share_bit0(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SHARE_BIT0));
  return true;
}

static bool scfirefox_get_define_page_bit_share_bit1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SHARE_BIT1));
  return true;
}

static bool scfirefox_get_define_page_bit_accessed(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_ACCESSED));
  return true;
}

static bool scfirefox_get_define_page_bit_not_global(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_NOT_GLOBAL));
  return true;
}

static bool scfirefox_get_define_page_bit_contiguous(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_CONTIGUOUS));
  return true;
}

static bool scfirefox_get_define_page_bit_pxn(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_PXN));
  return true;
}

static bool scfirefox_get_define_page_bit_xn(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_XN));
  return true;
}

static bool scfirefox_get_define_page_bit_softw1(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW1));
  return true;
}

static bool scfirefox_get_define_page_bit_softw2(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW2));
  return true;
}

static bool scfirefox_get_define_page_bit_softw3(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW3));
  return true;
}

static bool scfirefox_get_define_page_bit_softw4(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW4));
  return true;
}

static bool scfirefox_get_define_page_bit_softw5(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW5));
  return true;
}

static bool scfirefox_get_define_page_bit_softw6(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW6));
  return true;
}

static bool scfirefox_get_define_page_bit_softw7(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW7));
  return true;
}

static bool scfirefox_get_define_page_bit_softw8(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW8));
  return true;
}

static bool scfirefox_get_define_page_bit_softw9(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_PAGE_BIT_SOFTW9));
  return true;
}

static bool scfirefox_get_define_mt_bit_uc(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_UNCACHEABLE));
  return true;
}

static bool scfirefox_get_define_mt_bit_wt(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_THROUGH));
  return true;
}

static bool scfirefox_get_define_mt_bit_wb(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_WRITE_BACK));
  return true;
}

#endif


static bool scfirefox_get_define_page_level_pgd(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((int)LIBTEA_PGD));
  return true;
}

static bool scfirefox_get_define_page_level_pud(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((int)LIBTEA_PUD));
  return true;
}

static bool scfirefox_get_define_page_level_pmd(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((int)LIBTEA_PMD));
  return true;
}

static bool scfirefox_get_define_page_level_pte(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((int)LIBTEA_PTE));
  return true;
}

static bool scfirefox_get_define_page_level_page(JSContext *cx, unsigned argc, JS::Value *vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue((int)LIBTEA_PAGE));
  return true;
}

static bool scfirefox_get_define_flush_tlb_kernel(JSContext *cx, unsigned argc, JS::Value *vp){
  #if LIBTEA_LINUX
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_FLUSH_TLB_KERNEL));
  return true;
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: switching flush_tlb implementation is not supported on Windows.");
  return false;
  #endif
}

static bool scfirefox_get_define_flush_tlb_custom(JSContext *cx, unsigned argc, JS::Value *vp){
  #if LIBTEA_LINUX
  CallArgs args = CallArgsFromVp(argc, vp);
  args.rval().set(JS::NumberValue(LIBTEA_FLUSH_TLB_CUSTOM));
  return true;
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: switching flush_tlb implementation is not supported on Windows.");
  return false;
  #endif
}


/**
 * Switch between kernel and user-space paging implementations.
 *
 * :param implementation: The implementation to use, either LIBTEA_PAGING_IMPL_KERNEL, LIBTEA_PAGING_IMPL_USER, or LIBTEA_PAGING_IMPL_USER_PREAD
 */
static bool set_paging_implementation(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 4){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_paging_implementation takes 1 argument (implementation).");
    return false;
  }

  int implementation;
  JS::ToInt32(cx, args.get(0), &implementation);

  libtea_set_paging_implementation(scfirefox_instance, implementation);
  return true;
}


/**
 * Sets a bit in the PTE of an address.
 *
 * :param addr: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to set (one of SCFirefox.PAGE_BIT_*)
 */
static bool set_addr_page_bit(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_addr_page_bit takes 3 arguments (addr, pid, bit).");
    return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  int pid, bit;
  JS::ToInt32(cx, args.get(1), &pid);
  JS::ToInt32(cx, args.get(2), &bit);

  /* Make sure address is page-aligned to avoid borking the PTEs and crashing the system */
  if(addr % 4096 != 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: address provided to set_addr_page_bit is not page-aligned! Aborting before we crash/BSOD the system.");
    return false;
  } 

  libtea_set_addr_page_bit(scfirefox_instance, (void*) addr, pid, bit);
  return true;
}


/**
 * Clears a bit in the PTE of an address.
 *
 * :param addr: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to clear (one of SCFirefox.PAGE_BIT_*)
 */
static bool clear_addr_page_bit(JSContext* cx, unsigned argc, Value* vp){
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3){
    JS_ReportErrorUTF8(cx, "SCFirefox error: clear_addr_page_bit takes 3 arguments (addr, pid, bit).");
    return false;
  }

  uint64_t addr;
  int pid, bit;
  JS::ToUint64(cx, args.get(0), &addr);
  JS::ToInt32(cx, args.get(1), &pid);
  JS::ToInt32(cx, args.get(2), &bit);

  /* Make sure address is page-aligned to avoid borking the PTEs and crashing the system */
  if(addr % 4096 != 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: address provided to clear_addr_page_bit is not page-aligned! Aborting before we crash/BSOD the system.");
    return false;
  } 

  libtea_clear_addr_page_bit(scfirefox_instance, (void*)addr, pid, bit);
  return true;
}


/**
 * Helper function to mark a page as present and ensure the kernel is aware of this. Linux only. Use in preference to libtea_set_addr_page_bit to avoid system crashes (only necessary for the special case of the present bit).
 *
 * :param addr: The virtual address
 * :param prot: Protection flags to apply (e.g. SCFirefox.PROT_READ)
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool mark_page_present(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX	
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: mark_page_present takes 2 arguments (addr, prot).");
    return false;
  }

  uint64_t addr;
  int prot;
  JS::ToUint64(cx, args.get(0), &addr);
  JS::ToInt32(cx, args.get(1), &prot);

  /* Make sure address is page-aligned to avoid borking the PTEs and crashing the system */
  if(addr % 4096 != 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: address provided to mark_page_present is not page-aligned! Aborting before we crash/BSOD the system.");
    return false;
  } 

  int ret = libtea_mark_page_present(scfirefox_instance, (void*)addr, prot);
  args.rval().set(JS::NumberValue(ret));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: mark_page_present is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Helper function to mark a page as not present and ensure the kernel is aware of this. Linux only. 
 * Use in preference to libtea_set_addr_page_bit to avoid system crashes (only necessary for the
 * special case of the present bit).
 *
 * :param addr: The virtual address
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool mark_page_not_present(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX	
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: mark_page_not_present takes 1 arguments (addr).");
    return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);

  /* Make sure address is page-aligned to avoid borking the PTEs and crashing the system */
  if(addr % 4096 != 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: address provided to mark_page_present is not page-aligned! Aborting before we crash/BSOD the system.");
    return false;
  } 

  int ret = libtea_mark_page_not_present(scfirefox_instance, (void*)addr);
  args.rval().set(JS::NumberValue(ret));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: mark_page_not_present is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Returns the value of a bit from the PTE of an address.
 *
 * :param addr: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to get (one of SCFirefox.PAGE_BIT_*)
 *
 * :return: The value of the bit (0 or 1)
 */
static bool get_addr_page_bit(JSContext* cx, unsigned argc, Value* vp){
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_addr_page_bit takes 3 arguments (addr, pid, bit).");
    return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  int pid, bit;
  JS::ToInt32(cx, args.get(1), &pid);
  JS::ToInt32(cx, args.get(2), &bit);

  /* Make sure address is page-aligned to avoid borking the PTEs and crashing the system */
  if(addr % 4096 != 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: address provided to get_addr_page_bit is not page-aligned! Aborting before we crash/BSOD the system.");
    return false;
  } 

  unsigned char ret_bit = libtea_get_addr_page_bit(scfirefox_instance, (void*) addr, pid, bit);
  if(ret_bit == 0) args.rval().set(JS::NumberValue(0));
  else args.rval().set(JS::NumberValue(1));
  return true;
}


/**
 * Reads the PFN from the PTE of an address. IMPORTANT: check if this has returned 0 before you use the value!
 * On Windows, the PFN will be 0 of the page has not yet been committed (e.g. if you have allocated but not accessed
 * the page).
 *
 * :param addr: The virtual address
 * :param pid: The PID of the process (0 for own process)
 *
 * :return: The page-frame number (PFN)
 */
static bool get_addr_pfn(JSContext* cx, unsigned argc, Value* vp){
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_addr_pfn takes 2 arguments (addr, pid).");
    return false;
  }

  uint64_t val;
  JS::ToUint64(cx, args.get(0), &val);
  uint64_t* address = (uint64_t*)val;
  int pid;
  JS::ToInt32(cx, args.get(1), &pid);

  size_t pfn = libtea_get_addr_pfn(scfirefox_instance, address, pid);
  args.rval().set(JS::NumberValue(pfn));
  return true;
}


/**
 * Sets the PFN in the PTE of an address.
 *
 * :param addr: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param pfn: The new page-frame number (PFN)
 */
static bool set_addr_pfn(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 3){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_addr_pfn takes 3 arguments (addr, pid, pfn).");
    return false;
  }

  uint64_t val, pfn;
  uint64_t* address;
  int pid;
  JS::ToUint64(cx, args.get(0), &val);
  address = (uint64_t*)val;
  JS::ToInt32(cx, args.get(1), &pid);
  JS::ToUint64(cx, args.get(2), &pfn);

  libtea_set_addr_pfn(scfirefox_instance, address, pid, pfn);
  return true;
}


/**
 * Returns the default page size of the system.
 *
 * :return: Page size of the system in bytes
 */
static bool get_pagesize(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  size_t pagesize = libtea_get_pagesize(scfirefox_instance);
  args.rval().set(JS::NumberValue(pagesize));
  return true;
}


/**
 * Returns the physical address width of the CPU. Supported on Linux x86 only.
 *
 * :return: Physical address width of the CPU
 */
static bool get_physical_address_width(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX && LIBTEA_X86
  size_t address_width = libtea_get_physical_address_width();
  args.rval().set(JS::NumberValue(address_width));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address_width is only supported on Linux x86.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Returns the physical address of the provided virtual address at the provided paging level. 
 * Supported on Linux x86 only.
 *
 * :param vaddr: The virtual address
 * :param level: The paging level to resolve the address at, e.g. SCFirefox.PAGE_LEVEL_PTE
 * :return: The physical address or LIBTEA_ERROR
 */
static bool get_physical_address_at_level(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX && LIBTEA_X86
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }  

  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address_at_level takes 2 arguments (vaddr, level).");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }
  
  uint64_t vaddr;
  int level;
  JS::ToUint64(cx, args.get(0), &vaddr);
  JS::ToInt32(cx, args.get(1), &level);
  
  size_t ret_vaddr = libtea_get_physical_address_at_level(scfirefox_instance, vaddr, (libtea_page_level)level);
  args.rval().set(JS::NumberValue(ret_vaddr));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: get_physical_address_at_level is only supported on Linux x86.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Retrieves the content of a physical page.
 *
 * :param pfn: The page-frame number (PFN) of the page to read
 * :param buffer: A scfirefox_malloc() buffer that is large enough to hold the content of the page
 */
static bool read_physical_page(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: read_physical_page takes 2 arguments (pfn, buffer).");
    return false;
  }

  uint64_t pfn;
  uint64_t buffer_addr;
  char* buffer;
  JS::ToUint64(cx, args.get(0), &pfn);
  JS::ToUint64(cx, args.get(1), &buffer_addr);
  buffer = (char*) buffer_addr;

  libtea_read_physical_page(scfirefox_instance, pfn, buffer);
  return true;
}


/**
 * Replaces the content of a physical page.
 *
 * :param pfn: The page-frame number (PFN) of the page to update
 * :param content: A scfirefox_malloc() buffer containing the new content of the page (must be the size of a physical page)
 */
static bool write_physical_page(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: write_physical_page takes 2 arguments (pfn, content).");
    return false;
  }

  uint64_t pfn;
  uint64_t content_addr;
  char* content;
  JS::ToUint64(cx, args.get(0), &pfn);
  JS::ToUint64(cx, args.get(1), &content_addr);
  content = (char*) content_addr;

  libtea_write_physical_page(scfirefox_instance, pfn, content);
  return true;
}


/**
 * Maps a physical address range. Linux only.
 *
 * :param paddr: The physical address to map
 * :param size: The size of the physical memory range to map
 * :param prot: Protection flags to apply (e.g. SCFirefox.PROT_READ)
 * :param use_dev_mem: Whether to use /dev/mem or /dev/umem (the latter does not support PROT_EXEC)
 * :return: A virtual address that can be used to access the physical range, or LIBTEA_ERROR
 */
static bool map_physical_address_range(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 4){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_physical_address_range takes 4 arguments (paddr, size, prot, use_dev_mem).");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t paddr, size;
  int prot;
  JS::ToUint64(cx, args.get(0), &paddr);
  JS::ToUint64(cx, args.get(1), &size);
  JS::ToInt32(cx, args.get(2), &prot);
  bool use_dev_mem = JS::ToBoolean(args.get(3));

  /* This method actually returns a void pointer */
  size_t vaddr = (size_t) libtea_map_physical_address_range(scfirefox_instance, paddr, size, prot, use_dev_mem);
  args.rval().set(JS::NumberValue(vaddr));
  return true;

  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: map_physical_address_range is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;
  #endif
}


/**
 * Unmaps a virtual address range. Note: Linux only.
 *
 * :param vaddr: The virtual address to unmap
 * :param size: The size of the memory range to unmap
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool unmap_address_range(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_LINUX
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 4){
    JS_ReportErrorUTF8(cx, "SCFirefox error: map_physical_address_range takes 4 arguments (paddr, size, prot, use_dev_mem).");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t vaddr, size;
  JS::ToUint64(cx, args.get(0), &vaddr);
  JS::ToUint64(cx, args.get(1), &size);

  int ret = libtea_unmap_address_range(vaddr, size);
  args.rval().set(JS::NumberValue(ret));
  return true;

  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: unmap_address_range is not supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;
  #endif
}


/**
 * Creates an additional virtual mapping at the provided page level to the physical address
 * backing the provided virtual address.
 *
 * :param vaddr: The virtual address
 * :param level: The page level to remap at (e.g. SCFirefox.PAGE_LEVEL_PTE)
 * :param size: The size of the region to remap
 * :param prot: Protection flags to apply (e.g. SCFirefox.PROT_READ)
 * :param use_dev_mem: Whether to use /dev/mem or /dev/umem (the latter does not support PROT_EXEC)
 * :return: A virtual address that can be used to access the physical range, or LIBTEA_ERROR
 */
static bool remap_address(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 5){
    JS_ReportErrorUTF8(cx, "SCFirefox error: remap_address takes 5 arguments (vaddr, level, size, prot, use_dev_mem).");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t vaddr;
  int level, prot;
  uint64_t size;
  JS::ToUint64(cx, args.get(0), &vaddr);
  JS::ToInt32(cx, args.get(1), &level);
  JS::ToUint64(cx, args.get(2), &size);
  JS::ToInt32(cx, args.get(3), &prot);
  bool use_dev_mem = JS::ToBoolean(args.get(4));

  size_t ret_vaddr = (size_t) libtea_remap_address(scfirefox_instance, vaddr, (libtea_page_level)level, size, prot, use_dev_mem);
  args.rval().set(JS::NumberValue(ret_vaddr));
  return true;
}


/**
 * Returns the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM).
 *
 * :param pid: The process ID (0 for own process)
 * :return: The paging root, i.e. the physical address of the first page table (PGD)
 */
static bool get_paging_root(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_paging_root takes 1 argument (pid).");
    return false;
  }

  uint64_t pid;
  JS::ToUint64(cx, args.get(0), &pid);

  size_t root = libtea_get_paging_root(scfirefox_instance, pid);
  args.rval().set(JS::NumberValue(root));
  return true;
}


/**
 * Sets the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM).
 *
 * :param pid: The process ID (0 for own process)
 * :param root: The new paging root, i.e. the physical address of the first page table (PGD)
 */
static bool set_paging_root(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_paging_root takes 2 arguments (pid, root).");
    return false;
  }

  uint64_t pid, root;
  JS::ToUint64(cx, args.get(0), &pid);
  JS::ToUint64(cx, args.get(1), &root);

  libtea_set_paging_root(scfirefox_instance, pid, root);
  return true;
}


/**
 * Flushes (invalidates) the TLB entry for the provided address on all CPUs.
 *
 * :param addr: The virtual address to invalidate
 */
static bool flush_tlb(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: flush_tlb takes 1 argument (addr).");
    return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);

  libtea_flush_tlb(scfirefox_instance, (void*)addr);
  return true;
}


/**
 * Changes the implementation used for flushing the TLB. Both implementations use the kernel module,
 * but SCFirefox.FLUSH_TLB_KERNEL uses the native kernel functionality and is much faster; it should
 * be preferred unless your kernel does not support the flush_tlb_mm_range function. Note: Linux only.
 *
 * :param implementation: SCFirefox.FLUSH_TLB_KERNEL or SCFirefox.FLUSH_TLB_CUSTOM
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool switch_flush_tlb_implementation(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: switch_flush_tlb_implementation takes 1 argument (implementation).");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  int implementation;
  JS::ToInt32(cx, args.get(0), &implementation);

  int ret = libtea_switch_flush_tlb_implementation(scfirefox_instance, implementation);
  args.rval().set(JS::NumberValue(ret));
  return true;
}


/**
 * A full serializing barrier specifically for paging (overwrites the paging root with its current value).
 *
 */
static bool paging_barrier(JSContext* cx, unsigned argc, Value* vp){

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }

  libtea_paging_barrier(scfirefox_instance);
  return true;
}


/**
 * Reads the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to reading the MSR 0x277 (x86) / MAIR_EL1 (ARM).
 *
 * :return: The memory types in the same format as in the IA32_PAT MSR / MAIR_EL1
 */
static bool get_memory_types(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  } 

  CallArgs args = CallArgsFromVp(argc, vp);
  size_t memory_types = libtea_get_memory_types(scfirefox_instance);

  args.rval().set(JS::NumberValue(memory_types));
  return true;
}


/**
 * Sets the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to writing to the MSR 0x277 (x86) / MAIR_EL1 (ARM) on all CPUs.
 *
 * :param mts: The memory types in the same format as in the IA32_PAT MSR / MAIR_EL1
 */
static bool set_memory_types(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_memory_types takes 1 argument (mts).");
    return false;
  }

  uint64_t mts;
  JS::ToUint64(cx, args.get(0), &mts);
  
  libtea_set_memory_types(scfirefox_instance, mts);
  return true;
}


/**
 * Reads the value of the provided memory type attribute (PAT/MAIR).
 *
 * :param mt: The PAT/MAIR ID (from 0 to 7)
 * :return: The PAT/MAIR value (e.g. SCFirefox.UNCACHEABLE)
 */
static bool get_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: get_memory_type takes 1 argument (mt).");
    return false;
  }

  uint8_t mt;
  JS::ToUint8(cx, args.get(0), &mt);
  
  /* Returns a char but it will be a value between 0 and 7 */
  char mt_char = libtea_get_memory_type(scfirefox_instance, (unsigned char) mt);
  args.rval().set(JS::NumberValue((int) mt_char));

  return true;
}


/**
 * Sets the value of the provided memory type attribute (PAT/MAIR).
 *
 * :param mt: The PAT/MAIR ID (from 0 to 7)
 * :param value: The PAT/MAIR value (e.g. SCFIREFOX_UNCACHEABLE)
 */
static bool set_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_memory_type takes 2 arguments (mt, value).");
    return false;
  }

  uint8_t mt, value;
  JS::ToUint8(cx, args.get(0), &mt); 
  JS::ToUint8(cx, args.get(1), &value);
  
  libtea_set_memory_type(scfirefox_instance, (unsigned char) mt, (unsigned char) value);
  return true;
}


/**
 * Generates a bitmask of all memory type attributes (PAT/MAIR) that are programmed to the provided value.
 *
 * :param mt: A memory type, i.e., PAT/MAIR value (e.g. SCFirefox.UNCACHEABLE)
 * :return: A bitmask where a set bit indicates that the corresponding PAT/MAIR has the provided type
 */
static bool find_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: find_memory_type takes 1 argument (mt).");
    return false;
  }

  uint8_t mt;
  JS::ToUint8(cx, args.get(0), &mt);
  
  /* Returns an unsigned char but it will be a value between 0 and 7 */
  unsigned char bitmask_char = libtea_find_memory_type(scfirefox_instance, (unsigned char) mt);
  args.rval().set(JS::NumberValue((int) bitmask_char));
  return true;
}


/**
 * Returns the first memory type attribute (PAT/MAIR) that is programmed to the provided memory type.
 *
 * :param mt: A memory type, i.e., PAT/MAIR value (e.g. SCFirefox.UNCACHEABLE)
 * :return: A PAT/MAIR ID, or -1 if no PAT/MAIR of this type was found
 */
static bool find_first_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: find_first_memory_type takes 1 argument (mt).");
    return false;
  }

  uint8_t mt;
  JS::ToUint8(cx, args.get(0), &mt);
  
  int id = libtea_find_first_memory_type(scfirefox_instance, (unsigned char) mt);
  args.rval().set(JS::NumberValue(id));
  return true;
}


/**
 * Returns a new page-table entry which uses the provided memory type (PAT/MAIR).
 *
 * :param entry: A page-table entry
 * :param mt: A PAT/MAIR ID (between 0 and 7)
 * :return: A new page-table entry with the provided memory type (PAT/MAIR)
 */
static bool apply_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: apply_memory_type takes 2 arguments (entry, mt).");
    return false;
  }

  uint64_t entry;
  uint8_t mt;
  JS::ToUint64(cx, args.get(0), &entry);
  JS::ToUint8(cx, args.get(1), &mt);
  
  size_t new_entry = libtea_apply_memory_type(entry, (unsigned char) mt);
  args.rval().set(JS::NumberValue(new_entry));
  return true;
}


/**
 * Returns the memory type (i.e., PAT/MAIR ID) which is used by a page-table entry.
 *
 * :param entry: A page-table entry
 * :return: A PAT/MAIR ID (between 0 and 7)
 */
static bool extract_memory_type(JSContext* cx, unsigned argc, Value* vp){
  
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    return false;
  }  

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: extract_memory_type takes 1 argument (entry).");
    return false;
  }

  uint64_t entry;
  JS::ToUint64(cx, args.get(0), &entry);
  
  /* Returns an unsigned char, but it will be a value between 0 and 7 */
  char id = (char) libtea_extract_memory_type(entry);
  args.rval().set(JS::NumberValue((int) id));
  return true;
}


/**
 * Returns a human-readable representation of a memory type (PAT/MAIR value).
 *
 * :param mt: A memory type (PAT/MAIR value, e.g. SCFirefox.UNCACHEABLE)
 * :return: A human-readable representation of the memory type
 */
static bool memory_type_to_string(JSContext* cx, unsigned argc, Value* vp){
  
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: memory_type_to_string takes 1 argument (mt).");
    return false;
  }

  uint8_t mt;
  JS::ToUint8(cx, args.get(0), &mt);

  const char* mt_string = libtea_memory_type_to_string((unsigned char) mt);
  JSString* js_decoded = JS_NewStringCopyN(cx, mt_string, strlen(mt_string));
  args.rval().setString(js_decoded);
  return true;
}


/**
 * Helper function to find and apply the provide memory type to the provided page.
 *
 * :param page: The virtual address of the page
 * :param mt: A memory type (PAT/MAIR value, e.g. SCFirefox.UNCACHEABLE)
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool set_page_cacheability(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  if (args.length() != 2){
    JS_ReportErrorUTF8(cx, "SCFirefox error: set_page_cacheability takes 2 arguments (page, mt).");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t page;
  uint8_t mt;
  JS::ToUint64(cx, args.get(0), &page);
  JS::ToUint8(cx, args.get(1), &mt);

  int ret = libtea_set_page_cacheability(scfirefox_instance, (void*) page, (unsigned char) mt);
  args.rval().set(JS::NumberValue(ret));
  return true;
}



/**
 * Prints a page table entry to the command prompt (not to the JS console!).
 *
 * :param addr: A virtual address
 */
static bool print_page_entry(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: print_page_entry takes 1 argument (addr).");
    return false;
  }

  uint64_t addr;
  JS::ToUint64(cx, args.get(0), &addr);
  libtea_page_entry libtea_entry = libtea_resolve_addr(scfirefox_instance, (void*)addr, 0);
  libtea_print_libtea_page_entry(libtea_entry);
  return true;
}


/* Windows-only functionality
 * ==========================
 */


/**
 * Pins the current thread to the provided core (Windows-only).
 *
 * :param core: The core the thread should be pinned to
 */
static bool pin_thread_to_core(JSContext* cx, unsigned argc, Value* vp){

  #if LIBTEA_WINDOWS
  CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
   JS_ReportErrorUTF8(cx, "SCFirefox error: pin_to_core takes 1 argument (core).");
   return false;
  }
  
  int core;
  JS::ToInt32(cx, args.get(0), &core);

  libtea_thread thread;
  thread = GetCurrentThread();
  libtea__pin_thread_to_core(thread, core);
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: pin_thread_to_core is only supported on Windows.");
  return false;	  
  #endif
}


/* Helper function */
#if LIBTEA_WINDOWS
LONG WINAPI windows_exception_handler(LPEXCEPTION_POINTERS ExceptionInfo){
  longjmp(libtea__trycatch_buf, 1);
  return EXCEPTION_CONTINUE_EXECUTION;
}
#endif


/**
 * Add an exception handler for all exception types (Windows-only). The handler will jump to the next instruction after the faulting instruction.
 */
static bool add_windows_exception_handler(JSContext* cx, unsigned argc, Value* vp){
	
  #if LIBTEA_WINDOWS	
  /* The 1 means make this the first handler called in the handler chain */
  windowsExceptionHandler = AddVectoredExceptionHandler(1, windows_exception_handler);
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: add_windows_exception_handler is only supported on Windows.");
  return false;	  
  #endif
}


/**
 * Remove an exception handler added with SCFirefox (Windows-only).
 */
static bool remove_windows_exception_handler(JSContext* cx, unsigned argc, Value* vp){
	
  #if LIBTEA_WINDOWS	
  RemoveVectoredExceptionHandler(windowsExceptionHandler);
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: remove_windows_exception_handler is only supported on Windows.");
  return false;	  
  #endif
}


/**
 * Tell Windows to trim as many pages as possible from the current process. Provides a method to clear a page's accessed bit
 * (not guaranteed, but likely to occur) without requiring the libtea driver.
 */
static bool clear_windows_working_set(JSContext* cx, unsigned argc, Value* vp){
	
  #if LIBTEA_WINDOWS 	
  int ret = EmptyWorkingSet(GetCurrentProcess());
  if(!ret){
    JS_ReportErrorUTF8(cx, "SCFirefox error: could not empty working set in clear_windows_working_set, error code %d\n", GetLastError());
    return false;
  }
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: clear_windows_working_set is only supported on Windows.");
  return false;	  
  #endif
}


/**
 * Lock the provided page with VirtualLock (Windows-only).
 * 
 * :param address: Virtual address of the page to lock
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool lock_windows_page(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_WINDOWS
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
    args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }  
  
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: lock_windows_page takes 1 argument (address).");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t address;
  JS::ToUint64(cx, args.get(0), &address);
  bool ret = VirtualLock((void*)address, 4096);
  if(ret == 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: VirtualUnlock returned error %d.", GetLastError());
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }
  args.rval().set(JS::NumberValue(LIBTEA_SUCCESS));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: lock_windows_page is only supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Unlock the provided page with VirtualUnlock (Windows-only).
 * 
 * :param address: Virtual address of the page to unlock
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
static bool unlock_windows_page(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);

  #if LIBTEA_WINDOWS
  if(!scfirefox_instance){
    JS_ReportErrorUTF8(cx, "SCFirefox error: not yet initialized or initialization failed.");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }  
  
  if (args.length() != 1){
    JS_ReportErrorUTF8(cx, "SCFirefox error: unlock_windows_page takes 1 argument (address).");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  uint64_t address;
  JS::ToUint64(cx, args.get(0), &address);
  bool ret = VirtualUnlock((LPVOID)address, 4096);
  if(ret == 0){
    JS_ReportErrorUTF8(cx, "SCFirefox error: VirtualUnlock returned error %d.", GetLastError());
    return false;
  }
  args.rval().set(JS::NumberValue(LIBTEA_SUCCESS));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: unlock_windows_page is only supported on Windows.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Attempts to isolate the provided CPU core by removing it from the affinity mask of all
 * running user processes (Windows-only). It is unfortunately not possible to modify the
 * affinity of system processes. This is an experimental function and is only enabled if
 * LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION is set to 1 in libtea_config.h.
 * 
 * On Linux, boot with the isolcpus=X parameter set or (preferred) use the cset-shield tool.
 *
 * :param core: The CPU core to isolate
 * :return: LIBTEA_SUCCESS on success, otherwise LIBTEA_ERROR
 */
static bool isolate_windows_core(JSContext* cx, unsigned argc, Value* vp){

  CallArgs args = CallArgsFromVp(argc, vp);
  
  #if LIBTEA_WINDOWS && LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION
  if (args.length() != 1) {
    JS_ReportErrorUTF8(cx, "SCFirefox error: isolate_windows_core takes 1 argument (core).");
	args.rval().set(JS::NumberValue(LIBTEA_ERROR));
    return false;
  }

  int core = 0;
  JS::ToInt32(cx, args.get(0), &core);
  int ret = libtea_isolate_windows_core(core);
  
  args.rval().set(JS::NumberValue(ret));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION is disabled in the libtea configuration.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


/**
 * Forces a page combining scan across the whole system (Windows-only). This is experimental and
 * is only enabled if LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION is set to 1 in libtea_config.h.
 * 
 * :return: The number of pages combined
 */
static bool force_memory_deduplication(JSContext* cx, unsigned argc, Value* vp){
  CallArgs args = CallArgsFromVp(argc, vp);
  
  #if LIBTEA_WINDOWS && LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION
  long long pagesCombined = libtea_force_memory_deduplication();
  args.rval().set(JS::NumberValue(pagesCombined));
  return true;
  
  #else
  JS_ReportErrorUTF8(cx, "SCFirefox error: LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION is disabled in the libtea configuration.");
  args.rval().set(JS::NumberValue(LIBTEA_ERROR));
  return false;	  
  #endif
}


#define SCFIREFOX_PROPERTY_ATTRIBUTES 0   //wanted to set JSPROP_PERMANENT | JSPROP_READONLY here, but the compiler isn't having it

/* All defines we want to make available to the user go here. */
static const JSPropertySpec scfirefox_properties[] = {
	
  JS_PSG("PROT_READ", scfirefox_get_define_prot_read, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PROT_WRITE", scfirefox_get_define_prot_write, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PROT_EXEC", scfirefox_get_define_prot_exec, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PROT_NONE", scfirefox_get_define_prot_none, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("PAGE_LEVEL_PGD", scfirefox_get_define_page_level_pgd, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("PAGE_LEVEL_PUD", scfirefox_get_define_page_level_pud, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("PAGE_LEVEL_PMD", scfirefox_get_define_page_level_pmd, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("PAGE_LEVEL_PTE", scfirefox_get_define_page_level_pte, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("PAGE_LEVEL_PAGE", scfirefox_get_define_page_level_page, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("FLUSH_TLB_KERNEL", scfirefox_get_define_flush_tlb_kernel, SCFIREFOX_PROPERTY_ATTRIBUTES),  
  JS_PSG("FLUSH_TLB_CUSTOM", scfirefox_get_define_flush_tlb_custom, SCFIREFOX_PROPERTY_ATTRIBUTES),
  
#if LIBTEA_X86
  JS_PSG("PAGE_BIT_PRESENT", scfirefox_get_define_page_bit_present, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_RW", scfirefox_get_define_page_bit_rw, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_USER", scfirefox_get_define_page_bit_user, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PWT", scfirefox_get_define_page_bit_pwt, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PCD", scfirefox_get_define_page_bit_pcd, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_ACCESSED", scfirefox_get_define_page_bit_accessed, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_DIRTY", scfirefox_get_define_page_bit_dirty, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PSE", scfirefox_get_define_page_bit_pse, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PAT", scfirefox_get_define_page_bit_pat, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_GLOBAL", scfirefox_get_define_page_bit_global, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW1", scfirefox_get_define_page_bit_softw1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW2", scfirefox_get_define_page_bit_softw2, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW3", scfirefox_get_define_page_bit_softw3, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PAT_LARGE", scfirefox_get_define_page_bit_pat_large, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW4", scfirefox_get_define_page_bit_softw4, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PKEY_BIT0", scfirefox_get_define_page_bit_pkey_bit0, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PKEY_BIT1", scfirefox_get_define_page_bit_pkey_bit1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PKEY_BIT2", scfirefox_get_define_page_bit_pkey_bit2, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PKEY_BIT3", scfirefox_get_define_page_bit_pkey_bit3, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_NX", scfirefox_get_define_page_bit_nx, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("UNCACHEABLE", scfirefox_get_define_mt_bit_uc, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_COMBINING", scfirefox_get_define_mt_bit_wc, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_THROUGH", scfirefox_get_define_mt_bit_wt, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_PROTECTED", scfirefox_get_define_mt_bit_wp, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_BACK", scfirefox_get_define_mt_bit_wb, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("UNCACHEABLE_MINUS", scfirefox_get_define_mt_bit_ucminus, SCFIREFOX_PROPERTY_ATTRIBUTES),
#elif LIBTEA_AARCH64
  JS_PSG("PAGE_BIT_TYPE_BIT0", scfirefox_get_define_page_bit_type_bit0, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_TYPE_BIT1", scfirefox_get_define_page_bit_type_bit1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_MAIR_BIT0", scfirefox_get_define_page_bit_mair_bit0, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_MAIR_BIT1", scfirefox_get_define_page_bit_mair_bit1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_MAIR_BIT2", scfirefox_get_define_page_bit_mair_bit2, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_NON_SECURE", scfirefox_get_define_page_bit_non_secure, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PERMISSION_BIT0", scfirefox_get_define_page_bit_permission_bit0, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PERMISSION_BIT1", scfirefox_get_define_page_bit_permission_bit1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SHARE_BIT0", scfirefox_get_define_page_bit_share_bit0, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SHARE_BIT1", scfirefox_get_define_page_bit_share_bit1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_ACCESSED", scfirefox_get_define_page_bit_accessed, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_NOT_GLOBAL", scfirefox_get_define_page_bit_not_global, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_CONTIGUOUS", scfirefox_get_define_page_bit_contiguous, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_PXN", scfirefox_get_define_page_bit_pxn, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_XN", scfirefox_get_define_page_bit_xn, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW1", scfirefox_get_define_page_bit_softw1, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW2", scfirefox_get_define_page_bit_softw2, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW3", scfirefox_get_define_page_bit_softw3, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW4", scfirefox_get_define_page_bit_softw4, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW5", scfirefox_get_define_page_bit_softw5, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW6", scfirefox_get_define_page_bit_softw6, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW7", scfirefox_get_define_page_bit_softw7, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW8", scfirefox_get_define_page_bit_softw8, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("PAGE_BIT_SOFTW9", scfirefox_get_define_page_bit_softw9, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("UNCACHEABLE", scfirefox_get_define_mt_bit_uc, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_THROUGH", scfirefox_get_define_mt_bit_wt, SCFIREFOX_PROPERTY_ATTRIBUTES),
  JS_PSG("WRITE_BACK", scfirefox_get_define_mt_bit_wb, SCFIREFOX_PROPERTY_ATTRIBUTES),
#else
#warning "Unsupported architecture - paging only supported on x86 and AArch64!"
#endif
  JS_PS_END
};


static const JSFunctionSpec scfirefox_functions[] = {
 JS_FN("init", init, 0, 0),
 JS_FN("init_nokernel", init_nokernel, 0, 0),
 JS_FN("cleanup", cleanup, 0, 0),
 JS_FN("get_virtual_address", get_virtual_address, 1, 0),
 JS_FN("access", access, 1, 0),
 JS_FN("access_illegal", access_illegal, 1, 0),
 JS_FN("access_b", access_b, 1, 0),
 JS_FN("access_b_illegal", access_b_illegal, 1, 0),
 JS_FN("access_speculative", access_speculative, 1, 0),
 JS_FN("prefetch", prefetch, 1, 0),
 JS_FN("prefetch_anticipate_write", prefetch_anticipate_write, 1, 0),
 JS_FN("flush", flush, 1, 0),
 JS_FN("flush_b", flush_b, 1, 0),
 JS_FN("barrier_start", barrier_start, 0, 0),
 JS_FN("barrier_end", barrier_end, 0, 0),
 JS_FN("speculation_barrier", speculation_barrier, 0, 0),
 JS_FN("timestamp", timestamp, 0, 0),
 JS_FN("measure_start", measure_start, 0, 0),
 JS_FN("measure_end", measure_end, 0, 0),
 JS_FN("set_timer", set_timer, 1, 0),
 JS_FN("specpoline", specpoline, 1, 0),
 JS_FN("get_current_core", get_current_core, 0, 0),
 JS_FN("get_hyperthread", get_hyperthread, 1, 0),
 JS_FN("pin_to_core", pin_to_core, 1, 0),
 JS_FN("get_current_process_id", get_current_process_id, 0, 0),
 JS_FN("get_physical_address", get_physical_address, 1, 0),
 JS_FN("get_physical_address_obj", get_physical_address_obj, 1, 0),
 JS_FN("open_shared_memory", open_shared_memory, 1, 0),
 JS_FN("close_shared_memory", close_shared_memory, 0, 0),
 JS_FN("start_leaky_thread", start_leaky_thread, 4, 0),
 JS_FN("stop_leaky_thread", stop_leaky_thread, 0, 0),
 JS_FN("map", map, 3, 0),
 JS_FN("map_file_by_offset", map_file_by_offset, 3, 0),
 JS_FN("map_file", map_file, 2, 0),
 JS_FN("munmap_file", munmap_file, 1, 0),
 JS_FN("find_index_of_nth_largest_num", find_index_of_nth_largest_num, 3, 0),
 JS_FN("write_system_reg", write_system_reg, 3, 0),
 JS_FN("read_system_reg", read_system_reg, 2, 0),
 JS_FN("disable_hardware_prefetchers", disable_hardware_prefetchers, 0, 0),
 JS_FN("enable_hardware_prefetchers", enable_hardware_prefetchers, 0, 0),
 JS_FN("set_cpu_pstate", set_cpu_pstate, 1, 0),
 JS_FN("restore_cpu_pstate", restore_cpu_pstate, 0, 0),
 JS_FN("scfirefox_malloc", scfirefox_malloc, 1, 0),
 JS_FN("scfirefox_free", scfirefox_free, 1, 0),
 JS_FN("scfirefox_mmap", scfirefox_mmap, 2, 0),
 JS_FN("scfirefox_munmap", scfirefox_munmap, 1, 0),
 JS_FN("scfirefox_memset", scfirefox_memset, 3, 0),
 JS_FN("scfirefox_sched_yield", scfirefox_sched_yield, 0, 0),
 JS_FN("get_instance", get_instance, 0, 0),

 JS_FN("get_threshold", get_threshold, 0, 0),
 JS_FN("set_threshold", set_threshold, 1, 0),
 JS_FN("flush_reload", flush_reload, 1, 0),
 JS_FN("flush_reload_time", flush_reload_time, 1, 0),
 JS_FN("calibrate_flush_reload", calibrate_flush_reload, 0, 0),
 JS_FN("flush_covert_channel", flush_covert_channel, 0, 0),
 JS_FN("get_cache_slice", get_cache_slice, 1, 0),
 JS_FN("get_cache_set", get_cache_set, 1, 0),
 JS_FN("build_eviction_set", build_eviction_set, 1, 0),
 JS_FN("evict", evict, 0, 0),
 JS_FN("evict_reload", evict_reload, 1, 0),
 JS_FN("calibrate_evict_reload", calibrate_evict_reload, 0, 0),
 JS_FN("prime", prime, 0, 0),
 JS_FN("prime_probe", prime_probe, 0, 0),
 JS_FN("measure_slice", measure_slice, 1, 0),
 JS_FN("cache_encode", cache_encode, 1, 0),
 JS_FN("cache_encode_dereference", cache_encode_dereference, 2, 0),
 JS_FN("cache_decode_from_to", cache_decode_from_to, 3, 0),
 JS_FN("cache_decode", cache_decode, 1, 0),
 JS_FN("cache_decode_nonull", cache_decode_nonull, 1, 0),
 JS_FN("numeric_cache_decode_histogram", numeric_cache_decode_histogram, 5, 0),

 JS_FN("set_paging_implementation", set_paging_implementation, 1, 0),
 JS_FN("set_addr_page_bit", set_addr_page_bit, 3, 0),
 JS_FN("clear_addr_page_bit", clear_addr_page_bit, 3, 0),
 JS_FN("mark_page_present", mark_page_present, 2, 0),
 JS_FN("mark_present_not_present", mark_page_not_present, 1, 0),
 JS_FN("get_addr_page_bit", get_addr_page_bit, 3, 0),
 JS_FN("get_addr_pfn", get_addr_pfn, 2, 0),
 JS_FN("set_addr_pfn", set_addr_pfn, 3, 0),
 JS_FN("get_pagesize", get_pagesize, 0, 0),
 JS_FN("read_physical_page", read_physical_page, 2, 0),
 JS_FN("write_physical_page", write_physical_page, 2, 0),
 JS_FN("map_physical_address_range", map_physical_address_range, 2, 0),
 JS_FN("unmap_address_range", unmap_address_range, 2, 0),
 JS_FN("remap_address", remap_address, 5, 0),
 JS_FN("get_paging_root", get_paging_root, 1, 0),
 JS_FN("set_paging_root", set_paging_root, 2, 0),
 JS_FN("flush_tlb", flush_tlb, 1, 0),
 JS_FN("switch_flush_tlb_implementation", switch_flush_tlb_implementation, 1, 0),
 JS_FN("paging_barrier", paging_barrier, 0, 0),
 JS_FN("get_physical_address_width", get_physical_address_width, 0, 0),
 JS_FN("get_physical_address_at_level", get_physical_address_at_level, 2, 0),
 JS_FN("get_memory_types", get_memory_types, 0, 0),
 JS_FN("set_memory_types", set_memory_types, 1, 0),
 JS_FN("get_memory_type", get_memory_type, 1, 0),
 JS_FN("set_memory_type", set_memory_type, 2, 0),
 JS_FN("find_memory_type", find_memory_type, 1, 0),
 JS_FN("find_first_memory_type", find_first_memory_type, 1, 0),
 JS_FN("apply_memory_type", apply_memory_type, 2, 0),
 JS_FN("extract_memory_type", extract_memory_type, 1, 0),
 JS_FN("memory_type_to_string", memory_type_to_string, 1, 0),
 JS_FN("set_page_cacheability", set_page_cacheability, 2, 0),
 JS_FN("print_page_entry", print_page_entry, 1, 0),

 JS_FN("pin_thread_to_core", pin_thread_to_core, 1, 0),
 JS_FN("add_windows_exception_handler", add_windows_exception_handler, 0, 0),
 JS_FN("remove_windows_exception_handler", remove_windows_exception_handler, 0, 0),
 JS_FN("clear_windows_working_set", clear_windows_working_set, 0, 0),
 JS_FN("lock_windows_page", lock_windows_page, 1, 0),
 JS_FN("unlock_windows_page", unlock_windows_page, 1, 0),
 JS_FN("isolate_windows_core", isolate_windows_core, 1, 0),
 JS_FN("force_memory_deduplication", force_memory_deduplication, 0, 0),
 
 JS_FS_END
};

static JSObject* CreateSCFirefoxObject(JSContext* cx, JSProtoKey key) {
  Handle<GlobalObject*> global = cx->global();
  RootedObject proto(cx, GlobalObject::getOrCreateObjectPrototype(cx, global));
  if (!proto) {
    return nullptr;
  }
  return NewTenuredObjectWithGivenProto(cx, &SCFirefoxClass, proto);
}

static const ClassSpec SCFirefoxClassSpec = {CreateSCFirefoxObject, nullptr, scfirefox_functions, scfirefox_properties};

const JSClass js::SCFirefoxClass = {"SCFirefox", 0, JS_NULL_CLASS_OPS, &SCFirefoxClassSpec};
