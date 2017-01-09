/* Stub to save our registers into the registerstash structure. */
        .globl save_registers
save_registers:
        /* rdi points at register stash structure. */
        movq %rbx, 0(%rdi)
        movq %rsp, 8(%rdi)
        movq %rbp, 16(%rdi)
        movq %r12, 24(%rdi)
        movq %r13, 32(%rdi)
        movq %r14, 40(%rdi)
        movq %r15, 48(%rdi)
        /* Return pointer gets clobbered when we return, because it's
	   effectively in our red zone even with -mno-red-zone, so have
	   to save it here. */
        movq (%rsp), %rax
        movq %rax, 56(%rdi)
        /* Return 0. Rehydration returns 1. */
        xor %eax, %eax
        ret
        
