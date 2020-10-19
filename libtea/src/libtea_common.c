
/* See LICENSE file for license and copyright information */

/* Start libtea_common.c */
//---------------------------------------------------------------------------

/* TODO debug compiler flags - Windows should ideally be -O2 but this seems to force the frame pointer
 * being omitted, which could cause problems with setjmp from a non main function.
 */

#include "libtea_common.h"
#include "module/libtea_ioctl.h"

/* Internal functions not included in API */
//---------------------------------------------------------------------------
#if LIBTEA_LINUX
libtea_inline void libtea__thread_create(int* tid, void** stack_ptr, int (*fnc)(void*), void* arg);
#else
libtea_inline void libtea__thread_create(libtea_thread* thread, LPVOID ignored, LPTHREAD_START_ROUTINE func, LPVOID param);
libtea_inline void libtea__pin_thread_to_core(libtea_thread thread, int core);
#endif
libtea_inline void libtea__thread_cancel(libtea_thread thread, void* stack);
uint64_t libtea__timestamp_perf(libtea_instance* instance);
uint64_t libtea__timestamp_counting_thread(libtea_instance* instance);
libtea_inline static void libtea__set_timer(libtea_instance* instance, libtea_timer timer);
libtea_inline void libtea__init_counter_thread(libtea_instance* instance);
libtea_inline void libtea__cleanup_counter_thread(libtea_instance* instance);
libtea_inline static void libtea__init_perf(libtea_instance* instance);
libtea_inline void libtea__cleanup_perf(libtea_instance* instance);
libtea_inline int libtea__get_numeric_sys_cmd_output(const char* cmd);


void libtea__unblock_signal(int signum) {
  #if LIBTEA_LINUX
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
  #else
  /* Can get away with doing nothing on Windows */
  #endif
}


void libtea__trycatch_segfault_handler(int signum) {
  int i;
  for(i = 1; i < 32; i++) {
    libtea__unblock_signal(i);
  }
  #if LIBTEA_LINUX
  siglongjmp(libtea__trycatch_buf, 1);
  #else
  longjmp(libtea__trycatch_buf, 1);
  #endif
}


libtea_inline void libtea__try_start_prep() {
  libtea__saved_sighandler[0] = signal(SIGILL, libtea__trycatch_segfault_handler);
  libtea__saved_sighandler[1] = signal(SIGFPE, libtea__trycatch_segfault_handler);
  libtea__saved_sighandler[2] = signal(SIGSEGV, libtea__trycatch_segfault_handler);
}


void libtea__sigill_handler(int signum) {
  #if LIBTEA_LINUX
  libtea__unblock_signal(SIGILL);
  longjmp(libtea__trycatch_buf, 1);
  #else
  longjmp(libtea__trycatch_buf, 1);
  #endif
}


#if LIBTEA_LINUX
libtea_inline void libtea__thread_create(int* tid, void** stack_ptr, int (*fnc)(void*), void* arg) {
  int stacksize = 4096;
  char* stack = (char*) mmap(0, stacksize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if(stack_ptr) *stack_ptr = stack;
  /* CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_PARENT|CLONE_IO */
  *tid = clone(fnc, stack + stacksize - sizeof(void*) * 2, 0x80008700, arg);
}
#else
void libtea__thread_create(libtea_thread* thread, LPVOID ignored, LPTHREAD_START_ROUTINE func, LPVOID param){
  *thread = CreateThread(NULL, 4096, func, param, 0, NULL);
  if(*thread==NULL) libtea_info("Error: failed to create thread in libtea__thread_create.");
}
#endif


libtea_inline void libtea__thread_cancel(libtea_thread thread, void* stack) {
  #if LIBTEA_LINUX
  if(thread > 0) {
    kill(thread, 2);
  }
  if(stack) {
    munmap(stack, 4096);
  }
  #else
  TerminateThread(thread, 1);
  #endif
}


libtea_inline uint64_t libtea__timestamp_perf(libtea_instance* instance) {
  #if LIBTEA_LINUX
  uint64_t result = 0;
  if (read(instance->perf_fd, &result, sizeof(result)) < (ssize_t)sizeof(result)) {
    return 0;
  }
  return result;
  #else 
  /* Closest Windows equivalent to the perf interface. Microsoft recommends over RDTSC. */
  LARGE_INTEGER time;
  QueryPerformanceCounter(&time);
  return (uint64_t)time.QuadPart;
  #endif
}


libtea_inline uint64_t libtea__timestamp_counting_thread(libtea_instance* instance) {
  return instance->thread_counter;
}


libtea_inline static void libtea__set_timer(libtea_instance* instance, libtea_timer timer) {
  libtea__cleanup_counter_thread(instance);

  if(timer == LIBTEA_TIMER_NATIVE) {
    instance->timer = (libtea_timer_function) libtea__arch_timestamp_native;
  }
  #if LIBTEA_X86
  else if(timer == LIBTEA_TIMER_NATIVE_AMD_ZEN2){
    instance->timer = (libtea_timer_function) libtea__arch_timestamp_native_amd_zen2;
  }
  else if(timer == LIBTEA_TIMER_NATIVE_AMD_ZEN){
    #if LIBTEA_LINUX
    if(instance->module_fd > 0){
    #else
    if(instance->module_fd != NULL){
    #endif
      instance->timer = (libtea_timer_function) libtea__arch_timestamp_native_amd_zen;
    }
    else{
      libtea_info("Could not set timer LIBTEA_TIMER_NATIVE_AMD_ZEN. Have you loaded the kernel module? Falling back to rdtsc.");
      instance->timer = (libtea_timer_function) libtea__arch_timestamp_native;
    }
  }
  #endif

  else if(timer == LIBTEA_TIMER_COUNTING_THREAD) {
    libtea__init_counter_thread(instance);
  }
  else if(timer == LIBTEA_TIMER_MONOTONIC_CLOCK) {
    instance->timer = (libtea_timer_function) libtea__arch_timestamp_monotonic;
  }
  else if(timer == LIBTEA_TIMER_PERF) {
    libtea__init_perf(instance);
  }
}


libtea_inline void libtea__init_counter_thread(libtea_instance* instance) {

  libtea__thread_create(&(instance->timing_thread), &(instance->timing_thread_stack), libtea__arch_counting_thread, (void*)&(instance->thread_counter));
  instance->timer = (libtea_timer_function) libtea__timestamp_counting_thread;

  #if LIBTEA_LINUX
  int current_cpu = sched_getcpu();
  sched_getaffinity(getpid(), sizeof(cpu_set_t), &(instance->cpumask));
  libtea_pin_to_core(getpid(), current_cpu);

  #if LIBTEA_HAVE_HYPERTHREADING
  /* Double check we *actually* have hyperthreading, even though the config claims we do */

  const char* cmd1 = LIBTEA_SHELL " -c 'cat /sys/devices/system/cpu/smt/active'";
  /* Older kernels do not provide this SMT control, so also try this */
  const char* cmd2 = LIBTEA_SHELL " -c 'cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | grep - | wc -l'";

  if(libtea__get_numeric_sys_cmd_output(cmd1) || libtea__get_numeric_sys_cmd_output(cmd2)){
    int hyper = libtea_get_hyperthread(current_cpu);
    if(hyper != LIBTEA_ERROR) {
      libtea_pin_to_core(instance->timing_thread, hyper);
    }
    else libtea_info("Error: could not get hyperthread in libtea__init_counter_thread. Is hyperthreading present/enabled?");
  }

  #endif

  #else
  int core = GetCurrentProcessorNumber();
  libtea__pin_thread_to_core(instance->timing_thread, core);
  //TODO if hyperthreading pin to hyperthread
  #endif
}


libtea_inline void libtea__cleanup_counter_thread(libtea_instance* instance) {
  #if LIBTEA_LINUX
  if(instance->timing_thread > 0) {
    libtea__thread_cancel(instance->timing_thread, instance->timing_thread_stack);
    instance->timing_thread_stack = NULL;
    instance->timing_thread = 0;
    sched_setaffinity(getpid(), sizeof(cpu_set_t), &(instance->cpumask));
  }
  #else
  if(instance->timing_thread != NULL) {
    libtea__thread_cancel(instance->timing_thread, NULL);
  }
  #endif
}


libtea_inline static void libtea__init_perf(libtea_instance* instance) {
  #if LIBTEA_LINUX
  instance->timer = (libtea_timer_function) libtea__timestamp_perf;
  static struct perf_event_attr attr;
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.size = sizeof(attr);
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_callchain_kernel = 1;
  instance->perf_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if(instance->perf_fd <= 0) libtea_info("Could not initialize perf. Are you running with root privileges?");
  #else
  /* No need to do anything - on Windows we use QueryPerformanceCounter instead, which needs no initialization */
  #endif
}


libtea_inline void libtea__cleanup_perf(libtea_instance* instance) {
  #if LIBTEA_LINUX
  if(instance->perf_fd){
      close(instance->perf_fd);
  }
  #endif
  return;
}


#if LIBTEA_WINDOWS
/* Helper function to count set bits in the processor mask. From Windows Dev Center */
libtea_inline int libtea__windows_count_set_bits(ULONG_PTR bitMask){
  int lshift = sizeof(ULONG_PTR)*8 - 1;
  int bitSetCount = 0;
  ULONG_PTR bitTest = (ULONG_PTR)1 << lshift;
  for (int i = 0; i <= lshift; ++i) {
    bitSetCount += ((bitMask & bitTest) ? 1 : 0);
    bitTest /= 2;
  }

  return bitSetCount;
}
#endif


/* cmd must include LIBTEA_SHELL if you want to run a shell command. We assume
 * there is only one line of integer output less than 200 chars long, as in the
 * case of getconf.
 */
libtea_inline int libtea__get_numeric_sys_cmd_output(const char* cmd){
  char output[200];
  int ret_val = -1;
  int sscanf_ret = -1;
  FILE *fp = libtea_popen(cmd, "r");
  if (fp == NULL){
    libtea_info("Error: libtea_popen failed in libtea__get_numeric_sys_cmd_output");
    goto libtea__get_numeric_sys_cmd_output_end;
  }
  if(fgets(output, sizeof(output), fp) == NULL){
    libtea_info("Error: fgets failed in libtea__get_numeric_sys_cmd_output");
    goto libtea__get_numeric_sys_cmd_output_end;
  }
  sscanf(output, "%d", &ret_val);
  libtea__get_numeric_sys_cmd_output_end:
  if(fp) libtea_pclose(fp);
  if(ret_val == -1){
    libtea_info("Error: libtea__get_numeric_sys_cmd_output failed. Failed to execute command: %s.", cmd);
  }
  return ret_val;
}


#if LIBTEA_LINUX
int libtea__load_thread(void* param) {
#else
DWORD WINAPI libtea__load_thread(LPVOID param) {
#endif
  libtea_thread_data* data = (libtea_thread_data*) param;
  if(data->addr != NULL){
    unsigned char* ptr = (unsigned char*) data->addr;
    ptr[0] = data->secret;
    libtea_speculation_barrier();
    while(1){
      libtea_access(ptr);
    }
  }
  else{
    unsigned char addr[10];
    addr[0] = data->secret;
    libtea_speculation_barrier();
    while(1){
      libtea_access(addr);
    }
  }
}


#if LIBTEA_LINUX
int libtea__store_thread(void* param) {
#else
DWORD WINAPI libtea__store_thread(LPVOID param) {
#endif
  libtea_thread_data* data = (libtea_thread_data*) param;
  if(data->addr != NULL){
    unsigned char* ptr = (unsigned char*) data->addr;
    while(1){
      ptr[0] = data->secret;
    }
  }
  else{
    unsigned char addr[10];
    while(1){
      addr[0] = data->secret;
    }
  }
}


#if LIBTEA_LINUX
int libtea__nop_thread(void* param) {
#else
DWORD WINAPI libtea__nop_thread(LPVOID param) {
#endif
  while(1){
    /* Doesn't seem to get optimized out, at least on debug JSShell build on Windows */
    LIBTEA_NOP();
  }
}

#if LIBTEA_LINUX
bool libtea__write_int_to_file(const char* path, int data){
  FILE* file = fopen(path, "w");
  if(!file) return false;
  int retval = fprintf(file, "%i", data);
  fclose(file);
  if(retval == 1) return true;
  else return false;
}


int libtea__read_int_from_file(const char* path){
  int data = -1;
  FILE* file = fopen(path, "r");
  if(!file) return -1;
  int retval = fscanf(file, "%i", &data);
  fclose(file);
  if(retval == 1) return data;
  else return -1;
}


bool libtea__set_minimum_pstate(libtea_instance* instance, int perf_percentage, bool restore){
  const char* minimum_pstate_path = "/sys/devices/system/cpu/intel_pstate/min_perf_pct";
  if(restore) return libtea__write_int_to_file(minimum_pstate_path, instance->last_min_pstate);
  else {
    instance->last_min_pstate = libtea__read_int_from_file(minimum_pstate_path);
    return libtea__write_int_to_file(minimum_pstate_path, perf_percentage);
  }
}


bool libtea__set_maximum_pstate(libtea_instance* instance, int perf_percentage, bool restore){
  const char* maximum_pstate_path = "/sys/devices/system/cpu/intel_pstate/max_perf_pct";
  if(restore) return libtea__write_int_to_file(maximum_pstate_path, instance->last_max_pstate);
  else{
    instance->last_max_pstate = libtea__read_int_from_file(maximum_pstate_path);
    return libtea__write_int_to_file(maximum_pstate_path, perf_percentage);
  }
}


bool libtea__disable_turbo_boost(libtea_instance* instance, bool restore){
  const char* turbo_boost_disable_path = "/sys/devices/system/cpu/intel_pstate/no_turbo";
  if(restore) return libtea__write_int_to_file(turbo_boost_disable_path, instance->last_turbo_boost_setting);
  else{
    instance->last_turbo_boost_setting = libtea__read_int_from_file(turbo_boost_disable_path);
    return libtea__write_int_to_file(turbo_boost_disable_path, 1);
  }
}
#endif


/* Public functions included in API */
//---------------------------------------------------------------------------

libtea_instance* libtea_init(){
  libtea_instance* instance = libtea_init_nokernel();

  #if LIBTEA_LINUX
  instance->module_fd = open(LIBTEA_DEVICE_PATH, O_RDONLY);
  if (instance->module_fd < 0) {
    libtea_info("Could not open Libtea module: %s", LIBTEA_DEVICE_PATH);
    return NULL;
  }
  #if LIBTEA_SUPPORT_PAGING
  instance->mem_fd = open("/dev/mem", O_RDWR);  //This can be mapped PROT_EXEC, libtea_umem can't
  instance->umem_fd = open("/proc/libtea_umem", O_RDWR);
  #endif

  #else
  instance->module_fd = CreateFile(LIBTEA_DEVICE_PATH, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
  if (instance->module_fd == INVALID_HANDLE_VALUE) {
    libtea_info("Could not open Libtea module: %s. Check that you have run LibteaLoader to load the driver and that you are running from an administrator command prompt.", LIBTEA_DEVICE_PATH);
    return NULL;
  }
  /* instance->umem_fd not supported, so leave it set to 0 */
  #endif

  #if LIBTEA_SUPPORT_PAGING
  libtea__paging_init(instance);
  #endif

  #if LIBTEA_SUPPORT_INTERRUPTS
  libtea__interrupts_init();
  #endif

  return instance;
}


libtea_instance* libtea_init_nokernel(){
  libtea_instance* instance = (libtea_instance*)malloc(sizeof(libtea_instance));
  if(!instance) return NULL;
  memset(instance, 0, sizeof(libtea_instance));

  #if LIBTEA_LINUX
  /* TODO currently this approach will provide the wrong number of physical cores if there are
   * multiple CPU packages.
   */
  const char* cmd1 = LIBTEA_SHELL " -c 'cat /sys/devices/system/cpu/cpu*/topology/core_id | wc -l'";
  const char* cmd2 = LIBTEA_SHELL " -c 'cat /sys/devices/system/cpu/cpu*/topology/core_id | uniq | wc -l'";
  instance->logical_cores = libtea__get_numeric_sys_cmd_output(cmd1);
  instance->physical_cores = libtea__get_numeric_sys_cmd_output(cmd2);
  if(instance->physical_cores <= 0 || instance->logical_cores <= 0){
    libtea_info("Error: Libtea could not obtain the number of cores. Is /proc/cpuinfo accessible, and are the grep, uniq, and wc binaries present?");
    return NULL;
  }
  
  #else
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION infoBuffer = NULL;
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION infoBufferHandle = NULL;
  DWORD length = 0;

  /* First attempt will fail but writes the size buffer we actually need into length */
  GetLogicalProcessorInformation(infoBuffer, &length); 

  if(GetLastError() != ERROR_INSUFFICIENT_BUFFER){
    libtea_info("Error getting processor information in Libtea initialization - cannot continue, returning NULL instance.");
    free(infoBuffer);
    return NULL;
  }
  infoBuffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION) malloc(length);
  bool success = GetLogicalProcessorInformation(infoBuffer, &length); 

  if(!success){
    libtea_info("Error getting processor information in Libtea initialization - cannot continue, returning NULL instance.");
    if(infoBuffer) free(infoBuffer);
    return NULL;
  }

  int physicalCores = 0;
  int logicalCores = 0;
  infoBufferHandle = infoBuffer;

  /* Parsing code adapted from Windows Dev Center */
  for (int i=0; i <= length; i += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)) {
    switch (infoBufferHandle->Relationship) {
      
      case RelationProcessorCore:
        physicalCores++;
        logicalCores += libtea__windows_count_set_bits(infoBufferHandle->ProcessorMask);
        break;

      default:
        break;
      }
      
      infoBufferHandle++;
  }

  free(infoBuffer);
  instance->physical_cores = physicalCores;
  instance->logical_cores = logicalCores;
  #endif

  libtea__arch_init_cpu_features(instance);

  /* Use best available timer */
  libtea__saved_sighandler[SIGILL] = signal(SIGILL, libtea__sigill_handler);
  bool done = false;
  int counter = 0;
  while(!done){
    if(counter == 0) libtea__set_timer(instance, LIBTEA_TIMER_NATIVE);
    else if(counter == 1 && (instance->is_intel && instance->logical_cores == 2 * instance->physical_cores)){
      libtea__set_timer(instance, LIBTEA_TIMER_COUNTING_THREAD);
    }
    else if(counter == 2 && (instance->is_intel && instance->logical_cores == 2 * instance->physical_cores)){
      libtea__set_timer(instance, LIBTEA_TIMER_MONOTONIC_CLOCK);
    }
    else if(counter == 1) libtea__set_timer(instance, LIBTEA_TIMER_PERF); 
    else libtea__set_timer(instance, LIBTEA_TIMER_MONOTONIC_CLOCK);

    if(!setjmp(libtea__trycatch_buf)) {
      uint64_t ts1 = libtea_timestamp(instance);
      int i;
      for(i = 0; i < 1000000; i++) {
        LIBTEA_NOP();
      }
      uint64_t ts2 = libtea_timestamp(instance);
      if(ts2 > ts1) done = true;
    }
    counter++;
  }
  signal(SIGILL, libtea__saved_sighandler[SIGILL]);

  #if LIBTEA_SUPPORT_CACHE
  if(libtea_init_cache(instance) != LIBTEA_SUCCESS) return NULL;
  #endif
  
  return instance;
}


void libtea_cleanup(libtea_instance* instance){

  if(instance != NULL){
    #if LIBTEA_SUPPORT_CACHE
    libtea_cleanup_cache(instance);
    #endif

    #if LIBTEA_SUPPORT_PAGING
    libtea__cleanup_paging(instance);
    #endif

    #if LIBTEA_SUPPORT_INTERRUPTS
    /* Ensure local APIC timer is restored on process exit */
    if (libtea_apic_lvtt){
      libtea_apic_timer_deadline(instance);
    }
    #endif

    #if LIBTEA_LINUX
    if(instance->module_fd > 0) close(instance->module_fd);
    libtea__cleanup_perf(instance);
    #else
    if(instance->module_fd != NULL) CloseHandle(instance->module_fd);
    #endif

    instance = NULL;
  }

};


/**
 * Accesses the given address speculatively. Success will vary depending on the microarchitecture
 * used (exact branch prediction implementation, ROB size etc).
 *
 * :param addr: Virtual address to access
 */
libtea_inline void libtea_access_speculative(void* addr){
  
  /* Pointer chasing to extend the transient window */
  long long unsigned int condition = 1;
  void* chase_me[9] = {0};
  chase_me[8] = &chase_me[7];
  chase_me[7] = &chase_me[6];
  chase_me[6] = &chase_me[5];
  chase_me[5] = &chase_me[4];
  chase_me[4] = &chase_me[3];
  chase_me[3] = &chase_me[2];
  chase_me[2] = &chase_me[1];
  chase_me[1] = &chase_me[0];
  chase_me[0] = &condition;
  #define libtea_pointer_chaser *((uintptr_t*) ********(uintptr_t********)chase_me[8])

  /* Optimum number of flushes varies, but don't want to put too much pressure on the cache hierarchy */
  libtea_flush(&chase_me[8]);

  /* Stall long enough for the above flushes to take effect */
  for(volatile int z = 0; z < 100; z++){ }

  if(libtea_pointer_chaser){
    libtea_access(addr);
  }

}


libtea_inline uint64_t libtea_timestamp(libtea_instance* instance) {
  return instance->timer(instance);
}


libtea_inline void libtea_measure_start(libtea_instance* instance) {
  instance->measure_start = instance->timer(instance);
}


libtea_inline uint64_t libtea_measure_end(libtea_instance* instance) {
  return instance->timer(instance) - instance->measure_start;
}


libtea_inline static void libtea_set_timer(libtea_instance* instance, libtea_timer timer) {
  libtea__set_timer(instance, timer);
}    


libtea_inline int libtea_get_hyperthread(int logical_core) {

  #if LIBTEA_LINUX
  char cpu_id_path[300];
  char buffer[16];
  snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/cpu%d/topology/core_id", logical_core);

  FILE* f = fopen(cpu_id_path, "r");
  volatile int dummy = fread(buffer, 16, 1, f);
  fclose(f);
  int phys = atoi(buffer);
  int hyper = LIBTEA_ERROR;

  DIR* dir = opendir("/sys/devices/system/cpu/");
  struct dirent* entry;
  while((entry = readdir(dir)) != NULL) {
    if(entry->d_name[0] == 'c' && entry->d_name[1] == 'p' && entry->d_name[2] == 'u' && (entry->d_name[3] >= '0' && entry->d_name[3] <= '9')) {
      
      /* Check core is actually online */
      snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/%s/online", entry->d_name);
      f = fopen(cpu_id_path, "r");
      /* Do continue to core_id check if it's NULL as sometimes this file does not exist, even though the CPU *is* online */
      if(f != NULL){
        dummy += fread(buffer, 16, 1, f);
        fclose(f);
        if(atoi(buffer) == 0) continue;
      }
      
      snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/%s/topology/core_id", entry->d_name);
      f = fopen(cpu_id_path, "r");
      if(f != NULL){
        dummy += fread(buffer, 16, 1, f);
        fclose(f);
        int logical = atoi(entry->d_name + 3);
        if(atoi(buffer) == phys && logical != logical_core) {
          hyper = logical;
          break;
        }
      }
    }
  }
  closedir(dir);
  return hyper;
  
  #else
  NO_WINDOWS_SUPPORT;
  return 0;
  #endif
}


/* Can take a thread or process pid_t on Linux, Windows needs a separate internal function for threads */
libtea_inline void libtea_pin_to_core(libtea_thread process, int core) {
  #if LIBTEA_LINUX
  cpu_set_t mask;
  mask.__bits[0] = 1 << core;
  sched_setaffinity(process, sizeof(cpu_set_t), &mask);

  #else
  DWORD_PTR newAffinityMask = 0;
  newAffinityMask |= (1 << core);
  bool set_success = SetProcessAffinityMask(process, newAffinityMask);
  if(!set_success){
    libtea_info("Error: failed to set process affinity mask in libtea_pin_to_core.");
  }
  #endif
}

#if LIBTEA_WINDOWS
libtea_inline void libtea__pin_thread_to_core(libtea_thread thread, int core) {
  DWORD newAffinityMask = 0;
  newAffinityMask |= (1 << core);
  DWORD_PTR oldAffinityMask = SetThreadAffinityMask(thread, newAffinityMask);
  if(oldAffinityMask == 0){  //This does not need dereferencing because DWORD_PTR is *not* a pointer
    int error = GetLastError();
    libtea_info("Error: failed to set thread affinity mask in libtea__pin_thread_to_core, last error is %d.", error);
  }
}
#endif


libtea_inline size_t libtea_get_physical_address(libtea_instance* instance, size_t vaddr) {

  #if LIBTEA_LINUX
  int fd = open("/proc/self/pagemap", O_RDONLY);
  uint64_t virtual_addr = (uint64_t)vaddr;
  size_t value = 0;
  //TODO assuming 4KB pagesize - could use instance->pagesize but we only initialize it in paging init
  off_t offset = (virtual_addr / 4096) * sizeof(value);
  int got = pread(fd, &value, sizeof(value), offset);
  if (got != 8) {
     libtea_info("Error: pread failed (return value %d), could not read 8-byte physical address", got);
     return LIBTEA_ERROR;
  }
  return (value << 12) | ((size_t)vaddr & 0xFFFULL);

  #else
  size_t val = 0;
  ULONG returnLength;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_PHYS_ADDR, (LPVOID)&vaddr, sizeof(vaddr), (LPVOID)&val, sizeof(val), &returnLength, 0);
  return val;
  #endif

}


libtea_inline size_t libtea_get_kernel_physical_address(libtea_instance* instance, size_t vaddr) {

  #if LIBTEA_LINUX
  /* Use this function to get the physical address of a kernel-space virtual address. Kernel virtual->physical address conversion is simple arithmetic,
   * but we need some kernel specific variables, so we call the Libtea driver to invoke the kernel's virt_to_phys function.
   */
  void* addr = (void*) vaddr;
  ioctl(instance->module_fd, LIBTEA_IOCTL_GET_KERNEL_PHYS_ADDR, &addr);
  return (size_t) addr;

  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;
  #endif

}


/* Summary of how Libtea handles files and mapping/unmapping
 * ===========================================================
 * tl;dr: Windows adds an extra handle to keep track of with every mapping, which is irritating
 * as we try to create the illusion here that it works identically on Linux and Windows.
 * 
 * HANDLE libtea_open_shared_memory(size_t size, libtea_file_ptr windowsMapping)
 * Not file-backed.
 * Linux - mmap.
 * Windows - file mapping returned in windowsMapping, file view returned as ret arg

 * int libtea_close_shared_memory(HANDLE mem, libtea_file_ptr windowsMapping, size_t size);
 * Linux - munmap mem.
 * Windows - unmap mem, close windowsMapping.

 * void* libtea_map_file_by_offset(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, int rw, size_t offset);
 * File-backed.
 * Linux - open file, mmap. File descriptor returned in fileHandle, mapping returned as ret arg.
 * Windows - not supported

 * void* libtea_map_file(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping, int rw);
 * File-backed.
 * Linux - open file, mmap. File descriptor returned in fileHandle, mapping returned as ret arg.
 * Windows - CreateFileA, CreateFileMappingA, MapViewOfFile. File descriptor returned as fileHandle, file mapping returned as windowsMapping, view returned as ret arg.

 * void* libtea_mmap(int buffer_size, libtea_file_ptr windowsMapping, int rw);
 * Not file-backed.
 * Linux - mmap, return mapping.
 * Windows - CreateFileMappingA, MapViewOfFile. File mapping returned in windowsMapping, view returned as ret arg.

 * int libtea_munmap_file(void* ptr, int buffer_size, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping);
 * File-backed.
 * Linux - munmap, close fileHandle.
 * Windows - UnmapViewOfFile, CloseHandle.

 * int libtea_munmap(void* ptr, int buffer_size, libtea_file_ptr windowsMapping);
 * Not file-backed.
 * Linux - munmap.
 * Windows - UnmapViewOfFile, CloseHandle if windowsMapping is provided.
*/


libtea_inline HANDLE libtea_open_shared_memory(size_t size, libtea_file_ptr windowsMapping){
  
  HANDLE mem;

  #if LIBTEA_LINUX
  mem = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
  if (mem == MAP_FAILED){
    return NULL;
  }

  #else
  *windowsMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, size, "LIBTEALEAK");
  /* NULL returned if mapping failed, so we will just return NULL as specified in API */
  int err = GetLastError();
  if(err == ERROR_ALREADY_EXISTS){
    libtea_info("Error: can't create shared memory in libtea_open_shared_memory, region already mapped!");
    return NULL;
  }
  mem = MapViewOfFile(*windowsMapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
  if(mem == NULL) {
    libtea_info("Error in libtea_open_shared_memory: MapViewOfFile failed.");
    CloseHandle(*windowsMapping);
    return NULL;
  }
  #endif 

  return mem;
}


libtea_inline int libtea_close_shared_memory(HANDLE mem, libtea_file_ptr windowsMapping, size_t size){
  
  #if LIBTEA_LINUX
  if(munmap(mem, size) < 0) {
    return LIBTEA_ERROR;
  }

  #else
  if( !UnmapViewOfFile(mem) ){
    return LIBTEA_ERROR;
  }
  if( !CloseHandle(*windowsMapping) ){
    return LIBTEA_ERROR;
  }
  #endif 

  return LIBTEA_SUCCESS;
}


libtea_thread libtea_start_leaky_thread(libtea_instance* instance, int type, unsigned char secret, HANDLE shared, int core){

  instance->leaky_thread_data.secret = secret;
  instance->leaky_thread_data.addr = shared;
  instance->leaky_thread_data.core = core;

  if(type==0) libtea__thread_create(&instance->leaky_thread, NULL, libtea__load_thread, &(instance->leaky_thread_data));
  else if(type==1) libtea__thread_create(&instance->leaky_thread, NULL, libtea__store_thread, &(instance->leaky_thread_data));
  else libtea__thread_create(&instance->leaky_thread, NULL, libtea__nop_thread, &(instance->leaky_thread_data));

  #if LIBTEA_LINUX
  libtea_pin_to_core(instance->leaky_thread, core);
  #else
  libtea__pin_thread_to_core(instance->leaky_thread, core);
  #endif

  return instance->leaky_thread;
}


void libtea_stop_leaky_thread(libtea_instance* instance){
  libtea__thread_cancel(instance->leaky_thread, NULL);
}


libtea_inline void* libtea_map_file_by_offset(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, int rw, size_t offset) {

  #if LIBTEA_LINUX
  int prot1 = O_RDONLY;
  int prot2 = PROT_READ;
  if(rw == 1){
    prot1 = O_WRONLY;
    prot2 = PROT_WRITE;
  }
  else if(rw == 2){
    prot1 = O_RDWR;
    prot2 = PROT_READ | PROT_WRITE;
  }

  *fileHandle = open(filename, prot1);
  if (*fileHandle < 0) {
    return NULL;
  }
  void* mapping = mmap(0, 4096, prot2, MAP_SHARED, *fileHandle, offset & ~(0xFFF));
  if (mapping == MAP_FAILED) {
    close(*fileHandle);
    return NULL;
  }
  return (char*) mapping + (offset & 0xFFF);
  
  #else
  NO_WINDOWS_SUPPORT;
  return NULL;
  #endif
}


libtea_inline void* libtea_map_file(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping, int rw) {

  #if LIBTEA_LINUX
  int prot1 = O_RDONLY;
  int prot2 = PROT_READ;
  if(rw == 1){
    prot1 = O_WRONLY;
    prot2 = PROT_WRITE;
  }
  else if(rw == 2){
    prot1 = O_RDWR;
    prot2 = PROT_READ | PROT_WRITE;
  }

  *fileHandle = open(filename, prot1);
  if (*fileHandle < 0) {
    libtea_info("Error in libtea_map_file: open failed. Check the filename is correct.");
    return NULL;
  }
  struct stat filestat;
  if (fstat(*fileHandle, &filestat) == -1) {
    libtea_info("Error in libtea_map_file: fstat failed.");
    close(*fileHandle);
    return NULL;
  }
  void* mapping = mmap(0, filestat.st_size, prot2, MAP_SHARED, *fileHandle, 0);
  if (mapping == MAP_FAILED) {
    libtea_info("Error in libtea_map_file: mmap failed.");
    close(*fileHandle);
    return NULL;
  }
  if (filesize != NULL) {
    *filesize = filestat.st_size;
  }
  return mapping;
  
  #else
  //TODO change security attributes - this handle cannot be inherited by child processes
  
  int prot = FILE_MAP_READ;
  
  if(rw == 1){
    prot = FILE_MAP_WRITE;    /* This is actually read/write access, unfortunately we can't have write-only access on Windows */
  }
  else if(rw == 2){
    prot = FILE_MAP_ALL_ACCESS;
  }

  *fileHandle = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(*fileHandle == INVALID_HANDLE_VALUE) {
    libtea_info("Error in libtea_map_file: CreateFileA failed. Check the filename is correct. Last error is %lu", GetLastError());
    return NULL;
  }
  LARGE_INTEGER li_size;
  if( !GetFileSizeEx(*fileHandle, &li_size) ) {
    libtea_info("Error in libtea_map_file: GetFileSizeEx failed. fileHandle is %p, last error is %lu", *fileHandle, GetLastError());
    CloseHandle(*fileHandle);
    return NULL;
  }
  DWORD size = (DWORD)(li_size.QuadPart);
  *windowsMapping = CreateFileMappingA(*fileHandle, NULL, PAGE_READWRITE | SEC_COMMIT, 0, size, NULL);
  if(*windowsMapping == NULL) {
    libtea_info("Error in libtea_map_file: CreateFileMappingA failed. Last error is %lu", GetLastError());
    CloseHandle(*fileHandle);
    return NULL;
  }
  void* mapping = MapViewOfFile(*windowsMapping, prot, 0, 0, size);
  if(mapping == NULL) {
    libtea_info("Error in libtea_map_file: MapViewOfFile failed. Last error is %lu", GetLastError());
    CloseHandle(*windowsMapping);
    CloseHandle(*fileHandle);
    return NULL;
  }
  *filesize = (size_t)(size);  /* Warning: assuming 64-bit size_t...as we do elsewhere */
  return mapping;
  #endif

}


libtea_inline void* libtea_mmap(int buffer_size, libtea_file_ptr windowsMapping, int rw) {

  void* ptr;
  
  #if LIBTEA_LINUX
  int prot = PROT_READ;
  if(rw == 1){
    prot = PROT_WRITE;
  }
  else if(rw == 2){
    prot = PROT_READ | PROT_WRITE;
  }
  ptr = mmap(0, buffer_size, prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
  if(ptr == MAP_FAILED) {
    return NULL;
  }

  #else
  int prot = FILE_MAP_READ;
  
  if(rw == 1){
    prot = FILE_MAP_WRITE;    /* This is actually read/write access, unfortunately we can't have write-only access on Windows */
  }
  else if(rw == 2){
    prot = FILE_MAP_ALL_ACCESS;
  }

  *windowsMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, buffer_size, NULL);
  if(*windowsMapping == NULL) return NULL;
  ptr = MapViewOfFile(*windowsMapping, prot, 0, 0, buffer_size);
  if(ptr == NULL) {
    CloseHandle(*windowsMapping);
    return NULL;
  }
  #endif

  return ptr;
}


libtea_inline int libtea_munmap_file(void* ptr, int buffer_size, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping) {
  int ret = LIBTEA_SUCCESS;

  #if LIBTEA_LINUX
  if(munmap(ptr, buffer_size) < 0){
    ret = LIBTEA_ERROR;
  }
  if(close(*fileHandle) < 0){
    ret = LIBTEA_ERROR;
  }

  #else
  if( !UnmapViewOfFile(ptr) ){
    ret = LIBTEA_ERROR;
  }
  if( !CloseHandle(*windowsMapping) ){
    ret = LIBTEA_ERROR;
  }
  if( !CloseHandle(*fileHandle) ){
    ret = LIBTEA_ERROR;
  }
  #endif

  return ret;
}


libtea_inline int libtea_munmap(void* ptr, int buffer_size, libtea_file_ptr windowsMapping) {
  int ret = LIBTEA_SUCCESS;

  #if LIBTEA_LINUX
  if(munmap(ptr, buffer_size) < 0){
    ret = LIBTEA_ERROR;
  }

  #else
  if( !UnmapViewOfFile(ptr) ){
    ret = LIBTEA_ERROR;
  }
  if(!CloseHandle(*windowsMapping)){
    ret = LIBTEA_ERROR;
  }
  #endif

  return ret;
}



libtea_inline int libtea_find_index_of_nth_largest_int(int* list, size_t nmemb, size_t n) {
  int* sorted = (int*) malloc(sizeof(int)*nmemb);
  size_t* idx = (size_t*) malloc(sizeof(size_t)*nmemb);
  size_t i, j;
  int tmp;
  memset(sorted, 0, nmemb);
  for(i = 0; i < nmemb; i++) {
    sorted[i] = list[i];
    idx[i] = i;
  }
  for(i = 0; i < nmemb; i++) {
    int swaps = 0;
    for(j = 0; j < nmemb - 1; j++) {
      if(sorted[j] < sorted[j + 1]) {
        tmp = sorted[j];
        sorted[j] = sorted[j + 1];
        sorted[j + 1] = tmp;
        tmp = idx[j];
        idx[j] = idx[j + 1];
        idx[j + 1] = tmp;
        swaps++;
      }
    }
    if(!swaps) break;
  }
  int ret_val = idx[n];
  free(sorted);
  free(idx);
  return ret_val;
}


libtea_inline int libtea_find_index_of_nth_largest_sizet(size_t* list, size_t nmemb, size_t n) {
  int* sorted = (int*) malloc(sizeof(int)*nmemb);
  size_t* idx = (size_t*) malloc(sizeof(size_t)*nmemb);
  size_t i, j;
  size_t tmp;
  memset(sorted, 0, nmemb);
  for(i = 0; i < nmemb; i++) {
    sorted[i] = list[i];
    idx[i] = i;
  }
  for(i = 0; i < nmemb; i++) {
    int swaps = 0;
    for(j = 0; j < nmemb - 1; j++) {
      if(sorted[j] < sorted[j + 1]) {
        tmp = sorted[j];
        sorted[j] = sorted[j + 1];
        sorted[j + 1] = tmp;
        tmp = idx[j];
        idx[j] = idx[j + 1];
        idx[j + 1] = tmp;
        swaps++;
      }
    }
    if(!swaps) break;
  }
  int ret_val = idx[n];
  free(sorted);
  free(idx);
  return ret_val;
}


libtea_inline int libtea_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val){
  return libtea__arch_write_system_reg(instance, cpu, reg, val);
}


libtea_inline size_t libtea_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg){
  return libtea__arch_read_system_reg(instance, cpu, reg);
}


libtea_inline void libtea_disable_hardware_prefetchers(libtea_instance* instance){
  libtea__arch_disable_hardware_prefetchers(instance);
}


libtea_inline void libtea_enable_hardware_prefetchers(libtea_instance* instance){
  libtea__arch_enable_hardware_prefetchers(instance);
}


/* Adapted from code at https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes */
#if LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION
libtea_inline int libtea_isolate_windows_core(int core){
  #if LIBTEA_WINDOWS
  DWORD processes[4096] = {0};
  DWORD bytesReturned = 0;
  int numProcesses = 0;
  int numIsolated = 0;
  if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) return LIBTEA_ERROR;
  numProcesses = bytesReturned / sizeof(DWORD);
  if(numProcesses > 4096){
    numProcesses = 4096;
    libtea_info("Max supported number of processes (4096) exceeded. Will only attempt to isolate first 4096 processes.");
  }
  for (int i = 0; i < numProcesses; i++){
    if(processes[i] != 0){
      HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, processes[i]);
      if(!process){
        /* Access is denied for system processes. Seems there's nothing we can do about this, even as admin or with
         * PROCESS_ALL_ACCESS privilege.
         */
        continue;
      }
      DWORD_PTR processAffinityMask;
      DWORD_PTR systemAffinityMask;
      bool get_success = GetProcessAffinityMask(process, &processAffinityMask, &systemAffinityMask);
      if(get_success){
        processAffinityMask &= ~(1 << core);
        bool set_success = SetProcessAffinityMask(process, processAffinityMask);
        if(set_success) numIsolated++;
      }
      CloseHandle(process);
    }
  }
  libtea_info("Managed to isolate %d processes out of %d processes total.", numIsolated, numProcesses);
  return LIBTEA_SUCCESS;
  
  #else
  libtea_info("Error: isolate_windows_core is only supported on Windows.");
  return LIBTEA_ERROR;
  #endif
}
#endif


libtea_inline int libtea_set_cpu_pstate(libtea_instance* instance, int perf_percentage){
  #if LIBTEA_LINUX
  if(libtea__set_minimum_pstate(instance, perf_percentage, false) && libtea__set_maximum_pstate(instance, perf_percentage, false) && libtea__disable_turbo_boost(instance, false)) return LIBTEA_SUCCESS;
  else return LIBTEA_ERROR;
  #else
  return LIBTEA_ERROR;
  #endif
}


libtea_inline int libtea_restore_cpu_pstate(libtea_instance* instance){
  #if LIBTEA_LINUX
  if(libtea__set_minimum_pstate(instance, 0, true) && libtea__set_maximum_pstate(instance, 0, true) && libtea__disable_turbo_boost(instance, true)) return LIBTEA_SUCCESS;
  else return LIBTEA_ERROR;
  #else
  return LIBTEA_ERROR;
  #endif
}


/* End libtea_common.c */
//---------------------------------------------------------------------------
