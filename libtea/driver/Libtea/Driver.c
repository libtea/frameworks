#include "ntifs.h"
#include "ntddk.h"

#define LIBTEA_SUPPORT_CACHE 1
#define LIBTEA_SUPPORT_PAGING 1
#include "../../module/libtea_ioctl.h"

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Libtea");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\LibteaLink");
PDEVICE_OBJECT DeviceObject = NULL;

#define IA32_PAT 0x277


VOID Unload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  IoDeleteSymbolicLink(&SymLinkName);
  IoDeleteDevice(DeviceObject);
  DbgPrint("Libtea: driver unloaded\r\n");
}


__pragma(pack(push, 1))
typedef struct {
  char content[4096];
  size_t paddr;
} PageContent;
__pragma(pack(pop))


static ULONG_PTR invalidate_tlb(ULONG_PTR addr) {
  __invlpg((void*)addr);
  return (ULONG_PTR)NULL;
}


static ULONG_PTR set_pat(ULONG_PTR pat) {
  __writemsr(IA32_PAT, pat);
  return (ULONG_PTR)NULL;
}


NTSTATUS DispatchDeviceCtl(PDEVICE_OBJECT DevObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DevObject);
  
  PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS status = STATUS_SUCCESS;
  ULONG returnLength = 0;
  PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
  PEPROCESS Process;
  SIZE_T transferred;
  MM_COPY_ADDRESS mem;
  PageContent* content;
  PHYSICAL_ADDRESS pa;
  SIZE_T val;
  PVOID vaddr;
  KAFFINITY cpuMask = 1ULL;
  KAFFINITY oldCpuMask = 1ULL;
  libtea_system_reg* systemReg;

  switch (irpsp->Parameters.DeviceIoControl.IoControlCode) {
    case LIBTEA_IOCTL_WRITE_PAGE:
      content = (PageContent*)buffer;
      DbgPrint("Libtea: writing page, physical address %zx\r\n", content->paddr);
      pa.QuadPart = content->paddr;
      vaddr = MmGetVirtualForPhysical(pa);
      mem.VirtualAddress = (PVOID)(content->content);
      DbgPrint("Libtea: write page, virtual address: %zx\r\n", vaddr);
      if (vaddr) {
        MmCopyMemory(vaddr, mem, 4096, MM_COPY_MEMORY_VIRTUAL, &transferred);
      }
      else {
        DbgPrint("Libtea: could not write to page!\r\n");
      }
      returnLength = 0;
      break;
    case LIBTEA_IOCTL_READ_PAGE:
      DbgPrint("Libtea: reading page %zx\r\n", *(SIZE_T*)buffer);
      mem.PhysicalAddress = *(PHYSICAL_ADDRESS*)buffer;
      MmCopyMemory(buffer, mem, 4096, MM_COPY_MEMORY_PHYSICAL, &transferred);
      returnLength = 4096;
      break;
    case LIBTEA_IOCTL_GET_CR3:
      DbgPrint("Libtea: getting CR3 for %x\r\n", *((SIZE_T*)buffer));
      if(PsLookupProcessByProcessId((HANDLE)(*((PHANDLE)buffer)), &Process) == STATUS_SUCCESS) {
        KAPC_STATE apcState;
        KeStackAttachProcess(Process, &apcState);
        SIZE_T cr3 = __readcr3();
        KeUnstackDetachProcess(&apcState);
        DbgPrint("Libtea: CR3 is %x\r\n", cr3);
        *((SIZE_T*)buffer) = cr3;
      }
      else {
        DbgPrint("Libtea: could not find process!\r\n");
        *((SIZE_T*)buffer) = 0;
      }
      returnLength = sizeof(SIZE_T);
      break;
    case LIBTEA_IOCTL_SET_CR3:
      DbgPrint("Libtea: setting CR3 for %x\r\n", *((SIZE_T*)buffer));
      if(PsLookupProcessByProcessId((HANDLE)(*((PHANDLE)buffer)), &Process) == STATUS_SUCCESS) {
        KAPC_STATE apcState;
        KeStackAttachProcess(Process, &apcState);
        __writecr3(*(((SIZE_T*)buffer) + 1));
        KeUnstackDetachProcess(&apcState);
        DbgPrint("Libtea: new CR3 is %zx\r\n", *(((SIZE_T*)buffer) + 1));
      }
      else {
        DbgPrint("Libtea: could not find process!\r\n");
      }
      returnLength = 0;
    case LIBTEA_IOCTL_FLUSH_TLB:
      DbgPrint("Libtea: flushing TLB for %zx\r\n", *((SIZE_T*)buffer));
      KeIpiGenericCall(invalidate_tlb, (ULONG_PTR)(*(SIZE_T*)buffer));
      returnLength = 0;
      break;
    case LIBTEA_IOCTL_READ_PHYS_VAL:
      DbgPrint("Libtea: reading physical value %zx\r\n", *(SIZE_T*)buffer);
      mem.PhysicalAddress = *(PHYSICAL_ADDRESS*)buffer;
      MmCopyMemory(buffer, mem, sizeof(SIZE_T), MM_COPY_MEMORY_PHYSICAL, &transferred);
      returnLength = sizeof(SIZE_T);
      break;
    case LIBTEA_IOCTL_WRITE_PHYS_VAL:
      val = *(((SIZE_T*)buffer) + 1);
      DbgPrint("Libtea: writing physical value %zx to %zx\r\n", val, *(SIZE_T*)buffer);
      pa.QuadPart = *(SIZE_T*)buffer;
      vaddr = MmGetVirtualForPhysical(pa);
      if (vaddr) {
        *(SIZE_T*)vaddr = val;
      }
      else {
        DbgPrint("Libtea: could not write to physical address!\r\n");
      }
      returnLength = 0;
      break;
    case LIBTEA_IOCTL_GET_PHYS_ADDR:
      __try{
        vaddr = (PVOID)(*(SIZE_T*)buffer);
        pa = MmGetPhysicalAddress(vaddr);
        DbgPrint("Libtea: got physical address %p for virtual address %p\r\n", pa.QuadPart, vaddr);
        *(SIZE_T*)buffer = pa.QuadPart;
      }
      __except(EXCEPTION_EXECUTE_HANDLER){
        DbgPrint("LIBTEA_IOCTL_GET_PHYS_ADDR in exception handler\r\n");
        *(SIZE_T*)buffer = 0;
      }
      returnLength = sizeof(SIZE_T);
      break;
    case LIBTEA_IOCTL_GET_PAT:
      *(SIZE_T*)buffer = __readmsr(IA32_PAT); 
      returnLength = sizeof(SIZE_T);
      break;
    case LIBTEA_IOCTL_SET_PAT:
      /* KeIPiGenericCall interrupts all cores and runs set_pat simultaneously on them */
      KeIpiGenericCall(set_pat, (ULONG_PTR)(*(SIZE_T*)buffer));
      returnLength = 0;
      break;
    case LIBTEA_IOCTL_GET_SYSTEM_REG:
      systemReg = (libtea_system_reg*) buffer;
      if(!systemReg){  
        status = STATUS_INVALID_PARAMETER; 
        returnLength = sizeof(libtea_system_reg);
        break;
      }
      __try{
        cpuMask |= (1ULL << systemReg->cpu);
        /* Lock to the relevant core to get core-specific MSR value */
        oldCpuMask = KeSetSystemAffinityThreadEx(cpuMask); 
        systemReg->val = (size_t) __readmsr(systemReg->reg);
        KeRevertToUserAffinityThreadEx(oldCpuMask);
      }
      __except(EXCEPTION_EXECUTE_HANDLER){
        systemReg->val = 0;
      }
      returnLength = sizeof(libtea_system_reg);
      break;
    case LIBTEA_IOCTL_SET_SYSTEM_REG:
      systemReg = (libtea_system_reg*) buffer;
      if(!systemReg){  
        status = STATUS_INVALID_PARAMETER; 
        returnLength = sizeof(libtea_system_reg);
        break;
      }
      __try{
        cpuMask |= (1ULL << systemReg->cpu);
        /* Lock to the relevant core to get core-specific MSR value */
        oldCpuMask = KeSetSystemAffinityThreadEx(cpuMask); 
        __writemsr(systemReg->reg, systemReg->val);
        KeRevertToUserAffinityThreadEx(oldCpuMask);
      }
      __except(EXCEPTION_EXECUTE_HANDLER){
        DbgPrint("LIBTEA_IOCTL_SET_SYSTEM_REG in exception handler\r\n");
      }
      returnLength = sizeof(libtea_system_reg);
      break;
    break;
    default:
      status = STATUS_INVALID_PARAMETER;
      break;
  }

  Irp->IoStatus.Information = returnLength;
  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

NTSTATUS DispatchPassThru(PDEVICE_OBJECT DevObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DevObject);

  PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS status = STATUS_SUCCESS;

  switch (irpsp->MajorFunction) {
    case IRP_MJ_CREATE:
      DbgPrint("Libtea: IRP create. New driver handle opened.\r\n");
      break;
    case IRP_MJ_CLOSE:
      DbgPrint("Libtea: IRP close. Last driver handle closed and released.\r\n");
      break;
    case IRP_MJ_CLEANUP:
      DbgPrint("Libtea: IRP cleanup. Last driver handle closed.\r\n");
      break;
    default:
      DbgPrint("Libtea: invalid major function %d for IRP.\r\n", irpsp->MajorFunction);
      status = STATUS_INVALID_PARAMETER;
      break;
    }

  Irp->IoStatus.Information = 0;
  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  int i;
  DriverObject->DriverUnload = Unload;
  DbgPrint("Libtea: initializing.\r\n");
  NTSTATUS status;

  status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
  if (!NT_SUCCESS(status)) {
    DbgPrint("Libtea: failed to create Libtea device.\r\n");
    return status;
  }

  status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
  if (!NT_SUCCESS(status)) {
    DbgPrint("Libtea: failed to create symbolic link.\r\n");
    IoDeleteDevice(DeviceObject);
    return status;
  }

  for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    DriverObject->MajorFunction[i] = DispatchPassThru;
  }

  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceCtl;
  DbgPrint("Libtea: successfully loaded.\r\n");
  return status;
}
