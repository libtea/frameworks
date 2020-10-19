
/* See LICENSE file for license and copyright information */

/* begin libtea_irq_entry.S */

/* ********************************************************************** */
    .data
    .align 0x1000
    .global libtea_ss_irq_fired, libtea_ss_irq_count, libtea_ss_irq_cpl, libtea_apic_base, libtea_tsc_aex
libtea_ss_irq_fired:
    .int 0x0
libtea_ss_irq_count:
    .int 0x0
libtea_ss_irq_cpl:
    .int 0xff
libtea_apic_base:
    .quad 0x0
libtea_tsc_aex:
    .quad 0x0;
    /* not sure there's a kernel stack we can use(?) */
libtea_ss_irq_rax:
    .quad 0x0
libtea_ss_irq_rdx:
    .quad 0x0

/* ********************************************************************** */
    .text
    .align 0x1000
    .global libtea_ss_irq_handler
libtea_ss_irq_handler:
    /* IRQ latency timestamp */
    mov %rax, libtea_ss_irq_rax(%rip)
    mov %rdx, libtea_ss_irq_rdx(%rip)
    rdtsc
    mov %eax, libtea_tsc_aex(%rip)

    /* IRQ bookkeeping */
    incl libtea_ss_irq_fired(%rip)
    incl libtea_ss_irq_count(%rip)
    movw %cs,  libtea_ss_irq_cpl(%rip)
    andw $0x3, libtea_ss_irq_cpl(%rip)

    /* libtea_apic_write(APIC_EOI, 0x0); */
    lea libtea_apic_base(%rip), %rax
    mov (%rax),%rax
    test %rax, %rax
    jz 1f
    add $0xb0, %rax
    movl $0x0, (%rax)
1:
    mov libtea_ss_irq_rax(%rip), %rax
    mov libtea_ss_irq_rdx(%rip), %rdx
    iretq

/* ********************************************************************** */
    .global libtea_irq_gate_func
libtea_irq_gate_func:
    call *libtea_irq_gate_callback(%rip)
    iretq

/* end libtea_irq_entry.S */