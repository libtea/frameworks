
/* See LICENSE file for license and copyright information */

/* Start libtea_cache.c */
//---------------------------------------------------------------------------

#include "libtea_cache.h"

/* Internal functions not included in API */
//---------------------------------------------------------------------------
libtea_inline void libtea__init_cache_info(libtea_instance* instance);
libtea_inline int libtea__log_2(const uint32_t x);
libtea_inline bool libtea__eviction_init(libtea_instance* instance);
libtea_inline void libtea__eviction_cleanup(libtea_instance* instance);
libtea_inline size_t libtea__eviction_get_lookup_index(libtea_instance* instance, size_t paddr);
libtea_inline bool find_congruent_addresses(libtea_instance* instance, size_t index, size_t paddr, size_t number_of_addresses);
libtea_inline static void libtea__cleanup_all(void);
//---------------------------------------------------------------------------

libtea_inline void libtea__init_cache_info(libtea_instance* instance) {

  /* If the arch-specific cache info method reports its info is incomplete, fallback to parsing sysfs */
  if(!libtea__arch_init_cache_info(instance)){

    instance->llc_partitions = 1;
    libtea_info("Assuming your LLC has only a single partition. If this is incorrect, please set the environment variable LIBTEA_LLC_PARTITIONS.");

    #if LIBTEA_LINUX
    const char* cmd1 = LIBTEA_SHELL " -c 'getconf LEVEL3_CACHE_SIZE'";
    instance->llc_size = libtea__get_numeric_sys_cmd_output(cmd1);
    if(instance->llc_size == -1) goto libtea__init_cache_info_err;

    /* getconf worked and LLC is level 3, so get all other params at this level, ignore level 4 victim caches */
    else if(instance->llc_size != 0){  
      const char* cmd2 = LIBTEA_SHELL " -c 'getconf LEVEL3_CACHE_ASSOC'";
      instance->llc_ways = libtea__get_numeric_sys_cmd_output(cmd2);
      const char* cmd3 = LIBTEA_SHELL " -c 'getconf LEVEL3_CACHE_LINESIZE'";
      instance->llc_line_size = libtea__get_numeric_sys_cmd_output(cmd3);
    }

    /* getconf worked but no level 3 cache, so try L2 */
    else{ 
      const char* cmd4 = LIBTEA_SHELL " -c 'getconf LEVEL2_CACHE_SIZE'";
      instance->llc_size = libtea__get_numeric_sys_cmd_output(cmd4);
      if(instance->llc_size <= 0) goto libtea__init_cache_info_err; //no L2 either, give up (assume L1 cannot be LLC)
      else { //LLC is L2
        const char* cmd5 = LIBTEA_SHELL " -c 'getconf LEVEL2_CACHE_ASSOC'";
        instance->llc_ways = libtea__get_numeric_sys_cmd_output(cmd5);
        const char* cmd6 = LIBTEA_SHELL " -c 'getconf LEVEL2_CACHE_LINESIZE'";
        instance->llc_line_size = libtea__get_numeric_sys_cmd_output(cmd6);
      }
    }
    return;

    libtea__init_cache_info_err:
      libtea_info("Error: could not automatically obtain the properties of the LLC. All subsequent library calls using cache properties will produce incorrect results. Please set the LIBTEA_LLC_* environment variables.");

    #else
    NO_WINDOWS_SUPPORT;
    #endif

  }
  
}

// ---------------------------------------------------------------------------
libtea_inline static void libtea_cleanup_cache(libtea_instance* instance) {
  libtea__eviction_cleanup(instance);
  libtea__cleanup_counter_thread(instance);
  libtea_munmap(instance->covert_channel, LIBTEA_COVERT_CHANNEL_OFFSET * LIBTEA_COVERT_CHANNEL_ENTRIES, &instance->covert_channel_handle);
  int i = 0;
  while(libtea__instances[i]) {
    if(libtea__instances[i] == instance) {
      libtea__instances[i] = NULL;
    }
    i++;
  }
}

// ---------------------------------------------------------------------------
libtea_inline int libtea__log_2(const uint32_t x) {
  if(x == 0) return 0;
  
  #if _MSC_VER
  return (31 - (int)__lzcnt(x));
  #else
  return (31 - __builtin_clz (x));
  #endif
}

// ---------------------------------------------------------------------------
libtea_inline bool libtea__eviction_init(libtea_instance* instance) {
  if (instance->eviction != NULL && instance->eviction != 0) {
    return false;
  }

  libtea_eviction* eviction = (libtea_eviction*) calloc(1, sizeof(libtea_eviction));
  if (eviction == NULL) {
    return false;
  }

  eviction->memory.mapping_size = 128 * 1024 * 1024;
  eviction->memory.mapping = (char*) libtea_mmap(eviction->memory.mapping_size, eviction->memory.handle, LIBTEA_READ_WRITE);
  if (eviction->memory.mapping == NULL) {
    free(eviction);
    return false;
  }
  time_t srand_init;
  srand((unsigned) time(&srand_init));
  for(int value = 0; value < (int)eviction->memory.mapping_size; value++){
    /* Initialize the pages to different values to avoid memory deduplication collapsing it */
    ((char*)eviction->memory.mapping)[value] = rand() % 256;
  }

  eviction->congruent_address_cache = (libtea_congruent_address_cache_entry*) calloc(instance->llc_sets * instance->llc_slices, sizeof(libtea_congruent_address_cache_entry));
  if (eviction->congruent_address_cache == NULL) {
    libtea_munmap(eviction->memory.mapping, eviction->memory.mapping_size, eviction->memory.handle);
    free(eviction);
    return false;
  }

  instance->eviction = eviction;

  return true;
}

// ---------------------------------------------------------------------------
libtea_inline void libtea__eviction_cleanup(libtea_instance* instance) {
  if (instance->eviction == NULL) {
    return;
  }

  if (instance->eviction->congruent_address_cache) {
    free(instance->eviction->congruent_address_cache);
  }

  if (instance->eviction->memory.mapping) {
    libtea_munmap(instance->eviction->memory.mapping, instance->eviction->memory.mapping_size, instance->eviction->memory.handle);
  }

  free(instance->eviction);
  instance->eviction = NULL;
}

// ---------------------------------------------------------------------------
libtea_inline size_t libtea__eviction_get_lookup_index(libtea_instance* instance, size_t paddr) {
  int slice_index = libtea_get_cache_slice(instance, paddr);
  int set_index = libtea_get_cache_set(instance, paddr);

  return (slice_index * instance->llc_sets) + set_index;
}

// ---------------------------------------------------------------------------
libtea_inline bool find_congruent_addresses(libtea_instance* instance, size_t index, size_t paddr, size_t number_of_addresses) {

  if (instance->eviction->congruent_address_cache[index].used == true) {
    if (instance->eviction->congruent_address_cache[index].n >= number_of_addresses) {
      return true;
    }
  }

  if (instance->eviction->congruent_address_cache[index].congruent_virtual_addresses == NULL || instance->eviction->congruent_address_cache[index].n < number_of_addresses) {
    instance->eviction->congruent_address_cache[index].congruent_virtual_addresses = (void**) realloc(instance->eviction->congruent_address_cache[index].congruent_virtual_addresses, (sizeof(libtea_congruent_address_cache_entry) * number_of_addresses));
  }

  size_t addr = 0;
  char* current = (char*) instance->eviction->memory.mapping;
  current += paddr % 4096;
  while (addr < number_of_addresses) {
      *current = addr + 1;
      size_t physical = libtea_get_physical_address(instance, (size_t)current);
      if (libtea__eviction_get_lookup_index(instance, physical) == index && physical != paddr) {
          instance->eviction->congruent_address_cache[index].congruent_virtual_addresses[addr] = current;
          addr++;
      }

      current += 4096;
  }

  if (addr != number_of_addresses) {
    return false;
  }

  instance->eviction->congruent_address_cache[index].n = addr;
  instance->eviction->congruent_address_cache[index].used = true;

  return true;
}

// ---------------------------------------------------------------------------
libtea_inline static void libtea__cleanup_all(void) {
  int i = 0;
  while(libtea__instances[i]) {
    libtea_cleanup(libtea__instances[i]);
    libtea__instances[i] = 0;
    i++;
  }
}

// ---------------------------------------------------------------------------
libtea_inline static int libtea_init_cache(libtea_instance* instance) {
  instance->llc_miss_threshold = 180;

  libtea__init_cache_info(instance);
  if(getenv("LIBTEA_LLC_SLICES")) {
    instance->llc_slices = atoi(getenv("LIBTEA_LLC_SLICES"));
    libtea_info("Configured LLC slice count with $LIBTEA_LLC_SLICES value %d", instance->llc_slices);
  }
  if(getenv("LIBTEA_LLC_LINE_SIZE")) {
    instance->llc_line_size = atoi(getenv("LIBTEA_LLC_LINE_SIZE"));
    libtea_info("Configured LLC line size with $LIBTEA_LLC_LINE_SIZE value %d", instance->llc_line_size);
  }
  if(getenv("LIBTEA_LLC_SETS")) {
    instance->llc_sets = atoi(getenv("LIBTEA_LLC_SETS"));
    libtea_info("Configured LLC set count with $LIBTEA_LLC_SETS value %d", instance->llc_sets);
  }
  if(getenv("LIBTEA_LLC_PARTITIONS")) {
    instance->llc_partitions = atoi(getenv("LIBTEA_LLC_PARTITIONS"));
    libtea_info("Configured LLC partitions count with $LIBTEA_LLC_PARTITIONS value %d", instance->llc_partitions);
  }

  if(!instance->llc_sets) instance->llc_sets = instance->llc_size / instance->llc_line_size / instance->llc_ways / instance->llc_partitions;
  int set_per_cpu = instance->llc_sets / instance->llc_slices;

  instance->llc_set_mask = ((1 << libtea__log_2(set_per_cpu)) - 1) << libtea__log_2(instance->llc_line_size);

  #if LIBTEA_LINUX
  struct sysinfo info;
  if(sysinfo(&info) < 0){
    libtea_info("Error: call to sysinfo failed when initializing Libtea cache functionality.");
    return LIBTEA_ERROR;
  }
  instance->physical_memory = (size_t) info.totalram * (size_t) info.mem_unit;
  
  #else
  MEMORYSTATUSEX memory_status;
  memory_status.dwLength = sizeof(memory_status);
  if(!GlobalMemoryStatusEx(&memory_status)){
    int err = GetLastError();
    libtea_info("Error: call to GlobalMemoryStatusEx failed with error code %d when initializing Libtea cache functionality.", err);
    return LIBTEA_ERROR;
  }
  instance->physical_memory = memory_status.ullTotalPhys; /* Amount of actual physical memory in bytes */
  #endif

  libtea__arch_init_direct_physical_map(instance);
  libtea__arch_init_eviction_strategy(instance);
  libtea__arch_init_prime_strategy(instance);

  instance->covert_channel = libtea_mmap(LIBTEA_COVERT_CHANNEL_OFFSET * LIBTEA_COVERT_CHANNEL_ENTRIES, &instance->covert_channel_handle, LIBTEA_READ_WRITE);
  time_t srand_init;
  srand((unsigned) time(&srand_init));
  for(int value = 0; value < LIBTEA_COVERT_CHANNEL_OFFSET * LIBTEA_COVERT_CHANNEL_ENTRIES; value++){
    /* Very very important to initialize the covert channel pages to different values to avoid memory deduplication collapsing the channel */
    ((char*)instance->covert_channel)[value] = rand() % 256;
  }
  for(int value = 0; value < LIBTEA_COVERT_CHANNEL_ENTRIES; value++) {
    libtea_flush((char*) instance->covert_channel + value * LIBTEA_COVERT_CHANNEL_OFFSET);
  }

  int instance_count;
  for(instance_count = 0; instance_count < (int)sizeof(libtea__instances) / (int)sizeof(libtea__instances[0]) - 1; instance_count++) {
    if(libtea__instances[instance_count] == NULL) {
      libtea__instances[instance_count] = instance;
      break;
    }
  }

  if(getenv("LIBTEA_HIT_THRESHOLD")) {
    instance->llc_hit_threshold = atoi(getenv("LIBTEA_HIT_THRESHOLD"));
    libtea_info("Configured LLC hit threshold with $LIBTEA_HIT_THRESHOLD value %d", instance->llc_hit_threshold);
  }
  if(getenv("LIBTEA_MISS_THRESHOLD")) {
    instance->llc_miss_threshold = atoi(getenv("LIBTEA_MISS_THRESHOLD"));
    libtea_info("Configured LLC miss threshold with $LIBTEA_MISS_THRESHOLD value %d", instance->llc_miss_threshold);
  }
  if(getenv("LIBTEA_EVICTION_STRATEGY")) {
    // C-D-L-S
    char* strategy = strdup(getenv("LIBTEA_EVICTION_STRATEGY"));
    instance->eviction_strategy.C = atoi(strtok(strategy, "-"));
    instance->eviction_strategy.D = atoi(strtok(NULL, "-"));
    instance->eviction_strategy.L = atoi(strtok(NULL, "-"));
    instance->eviction_strategy.S = atoi(strtok(NULL, "-"));
    libtea_info("Configured eviction strategy with $LIBTEA_EVICTION_STRATEGY value %s", strategy);
    free(strategy);
  }
  if(getenv("LIBTEA_PRIME_STRATEGY")) {
    // C-D-L-S
    char* strategy = strdup(getenv("LIBTEA_PRIME_STRATEGY"));
    instance->eviction_strategy.C = atoi(strtok(strategy, "-"));
    instance->eviction_strategy.D = atoi(strtok(NULL, "-"));
    instance->eviction_strategy.L = atoi(strtok(NULL, "-"));
    instance->eviction_strategy.S = atoi(strtok(NULL, "-"));
    libtea_info("Configured prime strategy with $LIBTEA_PRIME_STRATEGY value %s", strategy);
    free(strategy);
  }
  if(getenv("LIBTEA_DIRECT_PHYSICAL_MAP")) {
    instance->direct_physical_map = strtoull(getenv("LIBTEA_DIRECT_PHYSICAL_MAP"), NULL, 0);
    libtea_info("Configured direct physical map with $LIBTEA_DIRECT_PHYSICAL_MAP value %zu", instance->direct_physical_map);
  }

  if(getenv("LIBTEA_DUMP")) {
    printf("Libtea configuration\n");
    printf("* LLC: %d sets, %d ways, %d slices (line size: %d)\n", instance->llc_sets, instance->llc_ways, instance->llc_slices, instance->llc_line_size);
    printf("* Cache hit/miss threshold: [%d, %d]\n", instance->llc_hit_threshold, instance->llc_miss_threshold);
    printf("* CPU: %d physical / %d logical cores, %s, architecture: 0x%x, %s\n", instance->physical_cores, instance->logical_cores, instance->is_intel ? "Intel" : "Non-Intel", instance->cpu_architecture, instance->has_tm ? "with transactional memory support" : "no transactional memory support");
    
    #if LIBTEA_LINUX
    printf("* Memory: %zd bytes / Memory map @ 0x%zx\n", instance->physical_memory, instance->direct_physical_map);
    #else
    printf("* Memory: %zd bytes\n", instance->physical_memory);
    #endif

    printf("\n");
  }
    
  if (instance_count == 0) {
    atexit(libtea__cleanup_all);  /* Triggers cleanup later at exit, not now */
  }

  return LIBTEA_SUCCESS;
}



/* Public functions included in API */
//---------------------------------------------------------------------------

libtea_inline int libtea_flush_reload(libtea_instance* instance, void* addr) {
  libtea_measure_start(instance);
  libtea_access(addr);
  int time = (int)libtea_measure_end(instance);
  int hit = (time < instance->llc_miss_threshold) && (time > instance->llc_hit_threshold);
  libtea_flush_b(addr);  /* Noise substantially increases without a memory barrier here */
  return hit;
}


libtea_inline void libtea_calibrate_flush_reload(libtea_instance* instance) {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 4096*8*10;
  size_t dummy[4096*8];
  size_t* ptr = dummy;

  libtea_access(ptr);
  sched_yield();
  for (i = 0; i < count; i++) {
    libtea_measure_start(instance);
    libtea_access(ptr + (64 * i) % (4096*8));
    reload_time += libtea_measure_end(instance);
    sched_yield();
  }
  for (i = 0; i < count; i++) {
    libtea_flush_b(ptr + (64 * i) % (4096*8));
    sched_yield();
    libtea_measure_start(instance);
    libtea_access(ptr + (64 * i) % (4096*8));
    flush_reload_time += libtea_measure_end(instance);
    sched_yield();
  }
  reload_time /= count;
  flush_reload_time /= count;
  if(!getenv("LIBTEA_HIT_THRESHOLD")){
    instance->llc_hit_threshold = 0;      /* There is no need to have a hit threshold on most systems */
  }
  if(!getenv("LIBTEA_MISS_THRESHOLD")){
    instance->llc_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
  }
}


libtea_inline int libtea_get_cache_slice(libtea_instance* instance, size_t paddr) {

  if(!instance->is_intel){
    libtea_info("libtea_get_cache_slice is only supported on Intel CPUs. The returned value will be incorrect.");
    return 0;
  }

  static const int h0[] = { 6, 10, 12, 14, 16, 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32, 33, 35, 36 };
  static const int h1[] = { 7, 11, 13, 15, 17, 19, 20, 21, 22, 23, 24, 26, 28, 29, 31, 33, 34, 35, 37 };
  static const int h2[] = { 8, 12, 13, 16, 19, 22, 23, 26, 27, 30, 31, 34, 35, 36, 37 };

  int count = sizeof(h0) / sizeof(h0[0]);
  int hash = 0;
  if(instance->llc_slices <= 1) return hash;

  for (int i = 0; i < count; i++) {
    hash ^= (paddr >> h0[i]) & 1;
  }
  if(instance->llc_slices == 2) return hash;

  count = sizeof(h1) / sizeof(h1[0]);
  int hash1 = 0;
  for (int i = 0; i < count; i++) {
    hash1 ^= (paddr >> h1[i]) & 1;
  }
  if(instance->llc_slices == 4) return hash | (hash1 << 1);

  count = sizeof(h2) / sizeof(h2[0]);
  int hash2 = 0;
  for (int i = 0; i < count; i++) {
    hash2 ^= (paddr >> h2[i]) & 1;
  }
  if(instance->llc_slices == 8) return (hash2 << 2) | (hash1 << 1) | hash;

  return 0;
}


libtea_inline int libtea_get_cache_set(libtea_instance* instance, size_t paddr) {
  return (paddr & instance->llc_set_mask) >> libtea__log_2(instance->llc_line_size);
}


libtea_inline int libtea_build_eviction_set(libtea_instance* instance, libtea_eviction_set* set, size_t paddr) {
  if (instance->eviction == NULL || instance->eviction == 0) {
    libtea__eviction_init(instance);
  }

  set->addresses = instance->eviction_strategy.S + instance->eviction_strategy.C + instance->eviction_strategy.D;
  set->address = NULL;

  size_t index = libtea__eviction_get_lookup_index(instance, paddr);

  if (find_congruent_addresses(instance, index, paddr, set->addresses) == false) {
    return LIBTEA_ERROR;
  }

  set->address = instance->eviction->congruent_address_cache[index].congruent_virtual_addresses;

  return LIBTEA_SUCCESS;
}


libtea_inline int libtea_build_eviction_set_vaddr(libtea_instance* instance, libtea_eviction_set* set, size_t vaddr) {
  size_t paddr = libtea_get_physical_address(instance, (size_t)vaddr);
  return libtea_build_eviction_set(instance, set, paddr);
}


libtea_inline void libtea_evict(libtea_instance* instance, libtea_eviction_set set) {
  int s, c, d;
  for(s = 0; s <= instance->eviction_strategy.S; s += instance->eviction_strategy.L) {
    for(c = 0; c <= instance->eviction_strategy.C; c += 1) {
      for(d = 0; d <= instance->eviction_strategy.D; d += 1) {
        libtea_access(set.address[s + d]);
      }
    }
  }
}


libtea_inline int libtea_evict_reload(libtea_instance* instance, void* addr, libtea_eviction_set set) { 
  libtea_measure_start(instance);
  libtea_access(addr);
  int time = (int)libtea_measure_end(instance);
  int hit = (time < instance->llc_miss_threshold) && (time > instance->llc_hit_threshold);
  libtea_evict(instance, set);
  return hit;
}


libtea_inline void libtea_calibrate_evict_reload(libtea_instance* instance) {
  size_t reload_time = 0, evict_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;

  *ptr = 2;
  libtea_eviction_set ev;
  if(libtea_build_eviction_set_vaddr(instance, &ev, (size_t)ptr)) return;

  libtea_access(ptr);
  for (i = 0; i < count; i++) {
    libtea_measure_start(instance);
    libtea_access(ptr);
    reload_time += libtea_measure_end(instance);
  }
  for (i = 0; i < count; i++) {
    libtea_measure_start(instance);
    libtea_access(ptr);
    evict_reload_time += libtea_measure_end(instance);
    libtea_evict(instance, ev);
  }
  reload_time /= count;
  evict_reload_time /= count;

  instance->llc_hit_threshold = 0; /* There is no need to have a hit threshold on most systems */
  instance->llc_miss_threshold = (evict_reload_time + reload_time * 2) / 3;
}


libtea_inline void libtea_prime(libtea_instance* instance, libtea_eviction_set set) {
  int s, c, d;
  for(s = 0; s <= instance->prime_strategy.S; s += instance->prime_strategy.L) {
    for(c = 0; c <= instance->prime_strategy.C; c += 1) {
      for(d = 0; d <= instance->prime_strategy.D; d += 1) {
        libtea_access(set.address[s + d]);
      }
    }
  }
}


libtea_inline int libtea_prime_probe(libtea_instance* instance, libtea_eviction_set set) {
  libtea_measure_start(instance);
  libtea_prime(instance, set);
  return libtea_measure_end(instance);
}


libtea_inline size_t libtea_measure_slice(libtea_instance* instance, void* address) {

  if(!instance->is_intel){
    libtea_info("libtea_measure_slice is only supported on Intel CPUs. The returned value will be incorrect.");
    return 0;
  }

  int msr_unc_perf_global_ctr;
  int val_enable_ctrs;
  if(instance->cpu_architecture >= 0x16) {
    /* Skylake or newer */   
    msr_unc_perf_global_ctr = 0xe01;
    val_enable_ctrs = 0x20000000;
  }
  else {
    msr_unc_perf_global_ctr = 0x391;
    val_enable_ctrs = 0x2000000f;
  }
    
  /* Disable counters */
  if(libtea_write_system_reg(instance, 0, msr_unc_perf_global_ctr, 0x0)) {
    return -1ull;
  }

  /* Reset counters */
  for (int i = 0; i < instance->llc_slices; i++) {
    libtea_write_system_reg(instance, 0, 0x706 + i * 0x10, 0x0);
  }

  /* Select event to monitor */
  for (int i = 0; i < instance->llc_slices; i++) {
    libtea_write_system_reg(instance, 0, 0x700 + i * 0x10, 0x408f34);
  }

  /* Enable counting */
  if(libtea_write_system_reg(instance, 0, msr_unc_perf_global_ctr, val_enable_ctrs)) {
    return -1ull;
  }

  /* Monitor */
  int access = 10000;
  while (--access) {
    libtea_flush(address);
  }

  /* Read counter */
  size_t* cboxes = (size_t*) malloc(sizeof(size_t) * instance->llc_slices);
  for (int i = 0; i < instance->llc_slices; i++) {
    cboxes[i] = libtea_read_system_reg(instance, 0, 0x706 + i * 0x10);
  }
  free(cboxes);

  return libtea_find_index_of_nth_largest_sizet(cboxes, instance->llc_slices, 0);
}


libtea_inline void libtea_cache_encode(libtea_instance* instance, unsigned char value) {
  libtea_access((char*) instance->covert_channel + value * LIBTEA_COVERT_CHANNEL_OFFSET);
}


libtea_inline void libtea_cache_encode_dereference(libtea_instance* instance, char* ptr, int offset) {
  libtea_access((char*) instance->covert_channel + ptr[offset] * LIBTEA_COVERT_CHANNEL_OFFSET);
}

libtea_inline int libtea_cache_decode_from_to(libtea_instance* instance, int from, int to, bool use_mix) {
  if(use_mix){
    for(int i = 0; i < 256; i++) {
      int mix_i = ((i * 167) + 13) & 255;
      if(mix_i < from || mix_i > to) continue;
      if(libtea_flush_reload(instance, (char*) instance->covert_channel + mix_i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
        return mix_i;
      }
    }
  }
  else{
    for(int i = from; i <= to; i++) {
      if(libtea_flush_reload(instance, (char*) instance->covert_channel + i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
        return i;
      }
    }
  }
  return LIBTEA_ERROR;
}


libtea_inline int libtea_cache_decode(libtea_instance* instance, bool use_mix) {
  return libtea_cache_decode_from_to(instance, 0, LIBTEA_COVERT_CHANNEL_ENTRIES-1, use_mix);
}


libtea_inline int libtea_cache_decode_nonull(libtea_instance* instance, bool use_mix) {
  return libtea_cache_decode_from_to(instance, 1, LIBTEA_COVERT_CHANNEL_ENTRIES-1, use_mix);
}


libtea_inline void libtea_cache_decode_histogram_iteration(libtea_instance* instance, bool use_mix, bool print, int offset, int from, int to, int* hist){
  bool update = false;
  int decoded = libtea_cache_decode_from_to(instance, from, to, use_mix);
  if(decoded > 0 && decoded != LIBTEA_ERROR){
    hist[decoded]++;
    update = true;
  }

  /* Redraw histogram on update */
  if (print && update) {
    #if LIBTEA_LINUX
    printf("\x1b[2J");
    #else
    system("cls");
    #endif
    int max = 1;

    for (int i = from; i <= to; i++) {
      if (hist[i] > max) {
        max = hist[i];
      }
    }

    printf("\n");
    for (int i = from; i <= to; i++) {
      printf("%c: (%4d) ", i+offset, hist[i]);
      for (int k = 0; k < hist[i] * 60 / max; k++) {
        printf("#");
      }
      printf("\n");
    }

    fflush(stdout);
  }
}



libtea_inline void libtea_print_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to) {

  int* hist = (int*) malloc(sizeof(int)*LIBTEA_COVERT_CHANNEL_ENTRIES);
  memset(hist, 0, sizeof(int)*LIBTEA_COVERT_CHANNEL_ENTRIES);
  bool update = false;
  
  for(int reps=0; reps<iterations; reps++){

    if(activity != NULL) activity();

    if(use_mix){
      for(int i=0; i<256; i++){
        int mix_i = ((i * 167) + 13) % 256;
        if(mix_i < from || mix_i > to) continue;
        if(libtea_flush_reload(instance, (char*) instance->covert_channel + mix_i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
          hist[mix_i]++;
          update = true;
        }  
      }
    }
    else{
      for(int i=from; i<=to; i++){
        if(libtea_flush_reload(instance, (char*) instance->covert_channel + i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
          hist[i]++;
          update = true;
        }  
      }
    }

    /* Redraw histogram on update */
    if (update) {
      #if LIBTEA_LINUX
      printf("\x1b[2J");
      #else
      system("cls");
      #endif
      int max = 1;

      for (int i = from; i <= to; i++) {
        if (hist[i] > max) {
          max = hist[i];
        }
      }

      printf("\n");
      for (int i = from; i <= to; i++) {
        printf("%c: (%4d) ", i+offset, hist[i]);
        for (int k = 0; k < hist[i] * 60 / max; k++) {
          printf("#");
        }
        printf("\n");
      }

      fflush(stdout);
    }
    update = false;

    if(sleep_len > 0) {
      #if LIBTEA_LINUX
      usleep(sleep_len);
      #else
      if((sleep_len % 1000) != 0) {
        libtea_info("Warning: Windows can only sleep with millisecond precision.\nPlease adjust sleep_len to be a multiple of 1000.");
      }
      Sleep(sleep_len / 1000);
      #endif
    }

    if(yield) {
      #if LIBTEA_LINUX
      sched_yield();
      #else
      SwitchToThread();
      #endif
    }

  }
  free(hist);
}


libtea_inline int* libtea_numeric_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to) {

  int* hist = (int*) malloc(sizeof(int)*LIBTEA_COVERT_CHANNEL_ENTRIES);
  memset(hist, 0, sizeof(int)*LIBTEA_COVERT_CHANNEL_ENTRIES);
  
  for(int reps=0; reps<iterations; reps++){

    if(activity != NULL) activity();

    if(use_mix){
      for(int i=0; i<256; i++){
        int mix_i = ((i * 167) + 13) % 256;
        if(mix_i < from || mix_i > to) continue;
        if(libtea_flush_reload(instance, (char*) instance->covert_channel + mix_i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
          hist[mix_i]++;
        }  
      }
    }
    else{
      for(int i=from; i<=to; i++){
        if(libtea_flush_reload(instance, (char*) instance->covert_channel + i * LIBTEA_COVERT_CHANNEL_OFFSET)) {
          hist[i]++;
        }  
      }
    }

    if(sleep_len > 0) {
      #if LIBTEA_LINUX
      usleep(sleep_len);
      #else
      if((sleep_len % 1000) != 0) {
        libtea_info("Warning: Windows can only sleep with millisecond precision.\nPlease adjust sleep_len to be a multiple of 1000.");
      }
      Sleep(sleep_len / 1000);
      #endif
    }

    if(yield) {
      #if LIBTEA_LINUX
      sched_yield();
      #else
      SwitchToThread();
      #endif
    }

  }
  return hist;
}


void libtea_check_decoded_per_cacheline(char* decoded, char* expected, int length) {
  int failed = 0;
  for (int cacheline=0; cacheline<(length/64); cacheline++){
    int failed=0;
    for(int i=0; i<64; i++){
      int offset = i + cacheline*64;
      if(decoded[offset] != expected[offset]){
        failed++;
      }
    }
    printf("%.02f,", (double)(64-failed)/64);
  }
  printf("\n");
}


int libtea_check_decoded(char* decoded, char* expected, int length, bool print_results) {
  int failed = 0;
  for (int i=0; i<length; i++) {
    if (decoded[i] != expected[i]) {
      failed++;
      if (print_results) libtea_info("Expected 0x%02x at %d but got 0x%02x", expected[i], i, decoded[i]);
    }
  }
  if (failed && print_results) {
    libtea_info("[FAIL] %d/%d bytes incorrect", failed, length);
  }
  else if (print_results) {
    libtea_info("[SUCCESS] Recovered all %d bytes correctly", length);
  }
  return failed;
}


/* End libtea_cache.c */
//---------------------------------------------------------------------------
