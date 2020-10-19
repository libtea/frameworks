
/* See LICENSE file for license and copyright information */

/* begin libtea_aep_trampoline.S */

/*
 * ---------------------------------------------------------------------
 * Function: libtea_aep_trampoline
 *      Code that will be returned to after interrupting an enclave.
 *
 * Registers:
 *      RAX - ERESUME leaf
 *      RBX - TSC address
 *      RCX - AEP address
 */
    .text
    .global libtea_aep_trampoline
    .type libtea_aep_trampoline, @function
libtea_aep_trampoline:
    mov %rbx, libtea_tcs(%rip)

    /* Optional C function callback */
    lea libtea_aep_function(%rip), %rax
    mov (%rax), %rax
    test %rax, %rax
    je .Leresume
    call *%rax

.Leresume:
    incl libtea_eresume_cnt(%rip)
    mov libtea_tcs(%rip), %rbx              /* TCS address */
    lea libtea_aep_trampoline(%rip), %rcx   /* AEP address */

    prefetch libtea_tsc_eresume(%rip)
    mfence

    rdtsc
    mov %eax, libtea_tsc_eresume(%rip)

    mov $3, %rax                        /* ERESUME leaf */
    .byte 0x0f, 0x01, 0xd7              /* ENCLU */

/* end libtea_aep_trampoline.S */
