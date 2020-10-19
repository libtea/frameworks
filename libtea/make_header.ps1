# Example usage: powershell -ExecutionPolicy Bypass .\make_header.ps1 -build cache
# Note: Interrupts and Enclave modules not yet supported on Windows (Linux only)

param (
    [Parameter(Mandatory=$true)][string]$build
 )

Write-Output "Building configuration $build..."
if($build -eq "basic"){
    type ../LICENSE, configs\basic_config.h, libtea_config.h, module/libtea_ioctl.h, include\libtea_common.h, include\arch\libtea_arch.h, src\libtea_common.c, src\arch\x86\libtea_x86_common.c, FOOTER > libtea.i
}
elseif($build -eq "cache"){
    type ../LICENSE, configs\cache_config.h, libtea_config.h, module/libtea_ioctl.h, include\libtea_common.h, include\arch\libtea_arch.h, include\libtea_cache.h, src\libtea_common.c, src\arch\x86\libtea_x86_common.c, src\libtea_cache.c, src\arch\x86\libtea_x86_cache.c, FOOTER > libtea.i
}
elseif($build -eq "paging"){
    type ../LICENSE, configs\cache_paging_config.h, libtea_config.h, module/libtea_ioctl.h, include\libtea_common.h, include\arch\libtea_arch.h, include\libtea_cache.h, include\arch\libtea_arch_paging.h, include\arch\x86\libtea_x86_paging.h, include\libtea_paging.h, src\libtea_common.c, src\arch\x86\libtea_x86_common.c, src\libtea_cache.c, src\arch\x86\libtea_x86_cache.c, src\libtea_paging.c, src\arch\x86\libtea_x86_paging.c, FOOTER > libtea.i
}
else{
    Write-Output "Usage: powershell -ExecutionPolicy Bypass .\make_header.ps1 -build cache"
    Write-Output "Available build configurations are basic, cache, and paging."
}

(Get-Content -path libtea.i -Raw) -replace "#include `".*`"", "" > libtea2.i
(Get-Content -path libtea2.i -Raw).replace("/* See LICENSE file for license and copyright information */", "") | Out-File libtea.h -encoding utf8
rm libtea.i
rm libtea2.i
