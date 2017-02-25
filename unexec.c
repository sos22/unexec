#include "unexec.h"

#include <sys/personality.h>
#include <asm/prctl.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define KERN_BASE 0x7ffffffff000

#define offsetof(field, strct) ((unsigned long)&((strct *)0ul)->field)

int arch_prctl(int code, unsigned long * fsbase);

/* A thing which the trampoline is going to have to mmap. */
struct mapping {
    uint64_t start;
    uint64_t size;
    off_t offset;
    unsigned prot;
    unsigned flags;
    /* Special case for half-constructed tables: path ==
     * tramp->procselfexe means it needs to be mapped from the thing
     * we're writing. Initially, they have zero offset, and we fill it
     * in later. Note that this is pointer equality, not strcmp(). */
    const char * path; };

/* All of the registers which we have to restore before
 * save_registers() returns. */
/* Structure is shared with the assembler bits. */
struct registerstash {
    unsigned long rbx;
    unsigned long rsp;
    unsigned long rbp;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long ret; };

/* This is the structure which gets persisted into the new binary. It
 * has to contain enough information to restore the contents of memory
 * and registers. It cannot be extended while the result is
 * half-constructed, so we do an iterate of trying different potential
 * sizes. */
struct trampoline {
    unsigned allocated;
    unsigned used;
    /* What do we want brk() to return when we rehydrate? */
    unsigned long initialbrk;
    /* The thing which actually gets run when we start. */
    void * trampoline;
    /* What is the trampoline actually going to restore? */
    struct mapping * mappings;
    unsigned nrmappings;
    /* dup of /proc/sys/exe into trampoline. Special because struct
     * mapping give it special handling. */
    const char * procselfexe;
    /* How many phdrs do we have? */
    unsigned nrphdrs;
    /* What's the offset of the landing area in the binary? */
    uint64_t landingoffset;
    /* Copy of all call-clobbered registers, to restore after we
     * rehydrate. */
    struct registerstash stash;
    unsigned char allocator[]; };

int save_registers(struct registerstash *);

static void dump_trampoline(const struct trampoline * tramp) {
    printf("allocator: %d/%d\n", tramp->used, tramp->allocated);
    printf("tramp at %p\n", tramp->trampoline);
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        printf("%d/%d: %lx->%lx offset %lx prot %d flags %d path %s\n",
               x,
               tramp->nrmappings,
               tramp->mappings[x].start,
               tramp->mappings[x].start + tramp->mappings[x].size,
               tramp->mappings[x].offset,
               tramp->mappings[x].prot,
               tramp->mappings[x].flags,
               tramp->mappings[x].path); }
    printf("nr mappings %d\n", tramp->nrphdrs);
    printf("landing offset %lx\n", tramp->landingoffset); }

static void * alloc_with_mmap(size_t sz) {
    sz = (sz + sizeof(size_t) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    void * res = mmap(NULL,
                      sz,
                      PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS,
                      -1,
                      0);
    assert(res != MAP_FAILED);
    size_t * res_sz = res;
    res_sz[0] = sz;
    return res_sz + 1; }

static void free_with_mmap(void const * what) {
    if (what == NULL) return;
    size_t const * sizes = what;
    sizes--;
    assert(sizes[0] != 0);
    assert(!(sizes[0] & (PAGE_SIZE - 1)));
    munmap((void *)sizes, sizes[0]); }

static char * read_file(const char * path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t res_sz = 16370;
    char * res = alloc_with_mmap(res_sz);
    while (true) {
        ssize_t sz = read(fd, res, res_sz);
        if (sz < res_sz) {
            close(fd);
            if (sz < 0) {
                free_with_mmap(res);
                return NULL; }
            else {
                res[sz] = '\0';
                return res; } }
        lseek(fd, 0, SEEK_SET);
        res_sz = sz * 2;
        free_with_mmap(res);
        res = alloc_with_mmap(res_sz); } }

static void * alloc_in_trampoline(size_t sz, struct trampoline * tramp) {
    static char failure[PAGE_SIZE];
    assert(sz < sizeof(failure));
    tramp->used += sz;
    if (tramp->used > tramp->allocated) return failure;
    else return tramp->allocator + tramp->used - sz; }

static char * strdup_in_trampoline(const char *what, struct trampoline * tramp){
    size_t sz = strlen(what);
    void * res = alloc_in_trampoline(sz + 1, tramp);
    memcpy(res, what, sz + 1);
    return res; }

/* Build the lump of machine code which the ELF binary entry point
 * will point at. */
static void * alloc_trampoline_text(struct trampoline *out) {
    /* We need a valid fsbase to call into libc, for the PLT, so
     * restore it from the trampoline. */
    unsigned long fsbase;
    if (arch_prctl(ARCH_GET_FS, &fsbase) < 0) return NULL;
    asm(
        "    jmp end_trampoline\n"
        "start_trampoline:\n"
        /* Set personality and disable address
         * randomisation. Randomisation affects exec behaviour, so
         * need to re-exec if we changed anything. */
        "    mov %[___NR_personality], %%rax\n"
        "set_rsi_persona_no_random:\n"
        "    movq $0x123456789, %%rdi\n"
        "    movq %%rdi, %%rbx\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        "    cmpq %%rax, %%rbx\n"
        "    jne exec_self\n" /* re-exec */
        /* Set fsbase */
        "    movq %[_ARCH_SET_FS], %%rdi\n"
        "set_rsi_fsbase:\n"
        "    movq $0x123456789, %%rsi\n" /* patched to fsbase */
        "    mov %[___NR_arch_prctl], %%eax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        /* Extend trampoline with new argv and environ from stack. */
        /* First we need to find out how big the area is. */
        "    movq (%%rsp), %%rax\n" /* How many arguments do we have? */
        "    lea 16(%%rsp, %%rax, 8), %%rsi\n" /* Skip past arguments. */
        "1:  leaq 8(%%rsi), %%rsi\n" /* Skip past environment
                                      * variables until we get a NULL
                                      * pointer. */
        "    movq (%%rsi), %%rax\n"
        "    testq %%rax, %%rax\n"
        "    jnz 1b\n"
        "    movq -8(%%rsi), %%rdi\n" /* rdi is last environment var,
                                       * so walk it to the end. */
        "    xor %%al, %%al\n" /* find end of variable. */
        "    movq $-1, %%rcx\n"
        "    cld\n"
        "    repne; scasb\n" /* rdi is now end of bit of stack which
                                must be copied. */
        "    movq %%rdi, %%r15\n"
        "    movq $0xfff, %%rax\n" /* Round boundaries to pages, for
                                    * mmap */
        "    addq %%rax, %%rdi\n"
        "    notq %%rax\n"
        "    movq %%rsp, %%r14\n"
        "    andq %%rax, %%r14\n"
        "    andq %%rax, %%rdi\n"
        "    subq %%r14, %%rdi\n" /* rdi is how big an allocation we
                                   * need. */
        "    movq %%rdi, %%r14\n"
        "set_rdi_tramp_top:\n" /* ANON mmap to get space above the trampoline */
        "    movq $0x123456789, %%rdi\n"
        "    movq %%r14, %%rsi\n"
        "    movq %[READ_WRITE], %%rdx\n"
        "    movq %[PRIVATE_ANONYMOUS], %%r10\n"
        "    mov $-1, %%r8\n"
        "    mov $0, %%r9\n"
        "    mov %[___NR_mmap], %%rax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        "    movq %%rax, %%r8\n"
        "    addq %%r14, %%r8\n"
        "    movq %%rsp, %%rsi\n" /* copy stack to bounce zone we just
                                   * allocated. */
        "    movq %%rsp, (%%rax)\n" /* Top of bounce zone is old rsp,
                                     * so that we can fix up relative
                                     * pointers. */
        "    leaq 8(%%rax), %%rdi\n"
        "    movq %%r15, %%rcx\n"
        "    subq %%rsp, %%rcx\n"
        "    rep; movsb\n"
        /* munmap everything above the trampoline. */
        "    movq %%r8, %%rdi\n"
        "set_rsi_kern_base:\n"
        "    movq $0x123456789, %%rsi\n" /* patched later */
        "    subq %%r8, %%rsi\n"
        "    mov %[___NR_munmap], %%rax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        "set_r15_tramp:\n"
        "    movq $0x123456789, %%r15\n" /* Patched to @out later */
        "    movq %c[mappings](%%r15), %%r14\n" /* r14 is next mapping */
        "    mov %[sizeofmapping], %%eax\n"
        "    movq %c[nrmappings](%%r15), %%rbx\n"
        "    imul %%rbx, %%rax\n"
        "    addq %%r14, %%rax\n"
        "    movq %%rax, %%r13\n" /* r13 is sentinel mapping */
        "next_mapping:\n"
        "    cmpq %%r14, %%r13\n"
        "    je done_mappings\n"
        /* open the next thing to map */
        "    movq %c[offsetpath](%%r14), %%rdi\n"
        "    movq %[_O_RDONLY], %%rsi\n"
        "    movq %[___NR_open], %%rax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        "    movq %%rax, %%r12\n"
        /* XXX should probably make some attempt to check the world
         * still looks like what we expect; otherwise, this'll be
         * confusing. */
        /* Now do the mmap */
        "    movq %c[offsetstart](%%r14), %%rdi\n"
        "    movq %c[offsetsize](%%r14), %%rsi\n"
        "    movq %c[offsetprot](%%r14), %%rdx\n"
        "    movq %c[offsetflags](%%r14), %%r10\n"
        "    movq %%r12, %%r8\n"
        "    movq %c[offsetoffset](%%r14), %%r9\n"
        "    testq %[_MAP_ANONYMOUS], %%r10\n"
        "    jz 1f\n" /* Zap FD anonymous maps */
        "    movq $-1, %%r8\n"
        "1:\n"
        "    movq %[___NR_mmap], %%rax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        /* Anon maps need to be pread in. */
        "    testq %[_MAP_ANONYMOUS], %c[offsetflags](%%r14)\n"
        "    jz 1f\n"
        "    movq %%r12, %%rdi\n"
        "    movq %c[offsetstart](%%r14), %%rsi\n"
        "    movq %c[offsetsize](%%r14), %%rdx\n"
        "    movq %c[offsetoffset](%%r14), %%r10\n"
        "    movq %[___NR_pread], %%rax\n"
        "    syscall\n"
        "    cmpq %%rax, %c[offsetsize](%%r14)\n"
        "    jne syscall_failed\n"
        "1:\n"
        /* close the fd */
        "    movq %%r12, %%rdi\n"
        "    movq %[___NR_close], %%rax\n"
        "    syscall\n"
        "    testq %%rax, %%rax\n"
        "    js syscall_failed\n"
        /* Advance to next structure. */
        "    lea %c[sizeofmapping](%%r14), %%r14\n"
        "    jmp next_mapping\n"
        "done_mappings:\n"
        /* All mappings restored, r15 set to trampoline
         * structure. Restore call saved registers. */
        "    movq %c[stash_rbx](%%r15), %%rbx\n"
        "    movq %c[stash_rsp](%%r15), %%rsp\n"
        "    movq %c[stash_ret](%%r15), %%rsi\n"
        "    movq %%rsi, (%%rsp)\n"
        "    movq %c[stash_rbp](%%r15), %%rbp\n"
        "    movq %c[stash_r12](%%r15), %%r12\n"
        "    movq %c[stash_r13](%%r15), %%r13\n"
        "    movq %c[stash_r14](%%r15), %%r14\n"
        "    movq %c[stash_r15](%%r15), %%r15\n"
        /* save_registers() returns 1 in the new process. */
        "    mov $1, %%eax\n"
        "    ret\n"
        "syscall_failed:\n"
        "    ud2\n"
        "exec_self:\n"
        /* Have to re-run execve. stack is argc, then argv, then environ. */
        "    movq (%%rsp), %%rax\n"
        "    leaq 8(%%rsp), %%rsi\n" /* argv */
        "    leaq 8(%%rsi, %%rax, 8), %%rdx\n" /* env */
        "mov_proc_self_exe_rdi:\n"
        "    movq $0x123456778, %%rdi\n"
        "    mov %[___NR_execve], %%rax\n"
        "    syscall\n"
        "    jmp syscall_failed\n"
        "end_trampoline:\n"
        :
        : [mappings] "i" (offsetof(mappings, struct trampoline)),
          [sizeofmapping] "i" (sizeof(struct mapping)),
          [nrmappings] "i" (offsetof(nrmappings, struct trampoline)),
          [offsetpath] "i" (offsetof(path, struct mapping)),
          [offsetstart] "i" (offsetof(start, struct mapping)),
          [offsetsize] "i" (offsetof(size, struct mapping)),
          [offsetprot] "i" (offsetof(prot, struct mapping)),
          [offsetflags] "i" (offsetof(flags, struct mapping)),
          [offsetoffset] "i" (offsetof(offset, struct mapping)),
          [_O_RDONLY] "i" (O_RDONLY),
          [READ_WRITE] "i" (PROT_READ|PROT_WRITE),
          [PRIVATE_ANONYMOUS] "i" (MAP_PRIVATE|MAP_ANONYMOUS),
          [_ARCH_SET_FS] "i" (ARCH_SET_FS),
          [___NR_arch_prctl] "i" (__NR_arch_prctl),
          [___NR_close] "i" (__NR_close),
          [___NR_execve] "i" (__NR_execve),
          [___NR_mmap] "i" (__NR_mmap),
          [___NR_munmap] "i" (__NR_munmap),
          [___NR_open] "i" (__NR_open),
          [___NR_personality] "i" (__NR_personality),
          [___NR_pread] "i" (__NR_pread64),
          [stash_rbx] "i" (offsetof(stash.rbx, struct trampoline)),
          [stash_rsp] "i" (offsetof(stash.rsp, struct trampoline)),
          [stash_rbp] "i" (offsetof(stash.rbp, struct trampoline)),
          [stash_r12] "i" (offsetof(stash.r12, struct trampoline)),
          [stash_r13] "i" (offsetof(stash.r13, struct trampoline)),
          [stash_r14] "i" (offsetof(stash.r14, struct trampoline)),
          [stash_r15] "i" (offsetof(stash.r15, struct trampoline)),
          [stash_ret] "i" (offsetof(stash.ret, struct trampoline)),
          [_MAP_ANONYMOUS] "i" (MAP_ANONYMOUS)
        );
    extern const unsigned char start_trampoline[0];
    extern const unsigned char set_rsi_persona_no_random[0];
    extern const unsigned char set_rsi_fsbase[0];
    extern const unsigned char set_rdi_tramp_top[0];
    extern const unsigned char set_rsi_kern_base[0];
    extern const unsigned char set_r15_tramp[0];
    extern const unsigned char mov_proc_self_exe_rdi[0];
    extern const unsigned char end_trampoline[0];
    char * res = alloc_in_trampoline(end_trampoline - start_trampoline, out);
    memcpy(res, start_trampoline, end_trampoline - start_trampoline);
    *(unsigned long *)(res + 2 + (set_rsi_persona_no_random - start_trampoline)) =
        personality(0xffffffff) | ADDR_NO_RANDOMIZE;
    *(unsigned long *)(res + 2 + (set_rsi_fsbase - start_trampoline)) =
        (unsigned long)fsbase;
    unsigned long out_top = (unsigned long)out + out->allocated + sizeof(*out);
    *(unsigned long *)(res + 2 + (set_rdi_tramp_top - start_trampoline)) =
        out_top;
    *(unsigned long *)(res + 2 + (set_rsi_kern_base - start_trampoline)) =
        KERN_BASE;
    *(unsigned long *)(res + 2 + (set_r15_tramp - start_trampoline)) =
        (unsigned long)out;
    *(unsigned long *)(res + 2 + (mov_proc_self_exe_rdi - start_trampoline)) =
        (unsigned long)out->procselfexe;
    return res; }

/* glibc munges this in not terribly helpful ways, so use the syscall
 * directly. */
static unsigned long getbrk(void) { return syscall(__NR_brk, 0); }

/* Parse up the mappings file and figure out what we need to program
 * into the trampoline. */
static int parse_mappings(char * str, struct trampoline * out) {
    out->initialbrk = getbrk();
    out->used = 0;
    /* Every line in the mapping file needs a mapping operation. */
    out->nrmappings = 0;
    for (char * cursor = str; *cursor; cursor++) {
        out->nrmappings += *cursor == '\n'; }
    out->mappings = alloc_in_trampoline(
        sizeof(out->mappings[0]) * out->nrmappings,
        out);
    out->procselfexe = strdup_in_trampoline("/proc/self/exe", out);
    out->trampoline = alloc_trampoline_text(out);
    unsigned nrdone = 0;
    char * line_end;
    errno = 0;
    char * line_start;
    for (line_start = str; *line_start; line_start = line_end + 1) {
        for (line_end = line_start; *line_end != '\n'; line_end++) {
            assert(*line_end); }
        *line_end = '\0';
        char * cursor;
        struct mapping mapping = {};
        mapping.start = strtoul(line_start, &cursor, 16);
        if (*cursor != '-') goto fail;
        cursor++;
        uint64_t end = strtoul(cursor, &cursor, 16);
        if (*cursor != ' ') goto fail;
        mapping.size = end - mapping.start;
        cursor++;
        switch (*cursor) {
        case 'r':
            mapping.prot |= PROT_READ;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'w':
            mapping.prot |= PROT_WRITE;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'x':
            mapping.prot |= PROT_EXEC;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'p':
            mapping.flags = MAP_PRIVATE;
            break;
        case 's':
            mapping.flags = MAP_SHARED;
            break;
        default: goto fail; }
        cursor++;
        if (*cursor != ' ') goto fail;
        cursor++;
        uint64_t offset = strtoul(cursor, &cursor, 16);
        if (*cursor != ' ') goto fail;
        cursor++;
        /*major = */strtoul(cursor, &cursor, 16);
        if (*cursor != ':') goto fail;
        cursor++;
        /*minor = */strtoul(cursor, &cursor, 16);
        if (*cursor != ' ') goto fail;
        cursor++;
        /*inode = */strtoul(cursor, &cursor, 10);
        if (*cursor != ' ') goto fail;
        while (*cursor == ' ') cursor++;
        const char * path = cursor;
        /* Kernel handles vsyscall for us. */
        if (!strcmp(path, "[vsyscall]")) {
            *line_end = '\n';
            continue; }
        if (!strcmp(path, "[stack]")) {
            /* Stack is special: it needs to be GROWS_DOWN to handle
             * future stack expansion, but Linux doesn't let you
             * combine GROWS_DOWN and fd mapping, and has problems if
             * you put a GROWS_DOWN right below a FIXED. Answer: the
             * stack is mapped ANONYMOUS and filled with a pread. */
            mapping.flags |= MAP_ANONYMOUS | MAP_GROWSDOWN; }
        mapping.flags |= MAP_FIXED;
        /* Other things we need to fix up somehow. Options are phdrs
         * and mmaps. */
        /* Phdr is safe for any non-shared mapping. */
        bool can_use_phdr = mapping.flags != MAP_SHARED;
        /* mmap is a bit more tricky: Have to be able to read the
         * file, and if it's private in-memory content needs to
         * match file contents */
        bool can_use_mmap;
        /* No path -> cannot mmap */
        if (strlen(path) == 0) can_use_mmap = false;
        /* Anon -> cannot mmap */
        else if (mapping.flags & MAP_ANONYMOUS) can_use_mmap = false;
        else {
            if (errno) goto fail;
            /* path need to be readable */
            struct stat st;
            if (stat(path, &st) < 0) {
                if (errno != ENOENT) goto fail;
                can_use_mmap = false; }
            else if (!(mapping.prot & PROT_READ)) {
                /* Cannot read map -> assume that mmap is safe */
                can_use_mmap = true; }
            else {
                /* Needs to match backing store. */
                int fd = open(path, O_RDONLY);
                if (fd < 0) goto fail;
                const void * remap = mmap(NULL,
                                          mapping.size,
                                          PROT_READ,
                                          MAP_PRIVATE,
                                          fd,
                                          offset);
                close(fd);
                if (remap == MAP_FAILED) goto fail;
                can_use_mmap =
                    memcmp(remap, (const void *)mapping.start, mapping.size)
                    == 0;
                munmap((void *)remap, mapping.size); }
            errno = 0; }
        if (can_use_mmap) {
            /* If we can use an mmap then do it. */
            mapping.offset = offset;
            mapping.path = strdup_in_trampoline(path, out); }
        else if (can_use_phdr) {
            mapping.path = out->procselfexe; }
        else {
            /* Can't mmap, can't phdr -> we fail */
            goto fail; }
        assert(nrdone < out->nrmappings);
        out->mappings[nrdone] = mapping;
        nrdone++;
        *line_end = '\n'; }
    out->nrmappings = nrdone;
    if (errno) goto fail;
    return 0;
  fail:
    return -1; }

/* Go through the bits which need mmaps of the ELF binary and figure
 * out where we're putting the phdrs for them. */
static void place_phdrs(struct trampoline * tramp) {
    /* Need a phdr for the trampoline itself, which isn't included in
     * the basic mappings list, one for the GNUSTACK note, and one for
     * a dummy which sets initial brk. */
    unsigned nr_phdrs = 3;
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        nr_phdrs += tramp->mappings[x].path == tramp->procselfexe; }
    /* Leave space for headers */
    uint64_t offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * nr_phdrs;
    /* Page align */
    offset = (offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        if (tramp->mappings[x].path != tramp->procselfexe) continue;
        tramp->mappings[x].offset = offset;
        offset += tramp->mappings[x].size;
        tramp->mappings[x].path = tramp->procselfexe; }
    tramp->nrphdrs = nr_phdrs;
    tramp->landingoffset = offset; }

static int write_ehdr(int fd, const struct trampoline * tramp) {
    Elf64_Ehdr hdr = {};
    hdr.e_ident[EI_MAG0] = ELFMAG0;
    hdr.e_ident[EI_MAG1] = ELFMAG1;
    hdr.e_ident[EI_MAG2] = ELFMAG2;
    hdr.e_ident[EI_MAG3] = ELFMAG3;
    hdr.e_ident[EI_CLASS] = ELFCLASS64;
    hdr.e_ident[EI_DATA] = ELFDATA2LSB;
    hdr.e_ident[EI_OSABI] = ELFOSABI_LINUX;
    hdr.e_type = ET_EXEC;
    hdr.e_machine = EM_X86_64;
    hdr.e_version = EV_CURRENT;
    hdr.e_entry = (unsigned long)tramp->trampoline;
    hdr.e_phoff = sizeof(hdr);
    hdr.e_shoff = 0;
    hdr.e_flags = 0;
    hdr.e_ehsize = sizeof(hdr);
    hdr.e_phentsize = sizeof(Elf64_Phdr);
    hdr.e_phnum = tramp->nrphdrs;
    hdr.e_shentsize = sizeof(Elf64_Shdr);
    hdr.e_shnum = 0;
    hdr.e_shstrndx = SHN_UNDEF;
    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) return -1;
    else return 0; }

static int write_phdr(int fd, const struct mapping * mapping) {
    Elf64_Phdr phdr = {
        .p_type = PT_NULL,
        .p_vaddr = 0,
        .p_memsz = 0,
        .p_filesz = mapping->size,
        .p_offset = mapping->offset,
        .p_flags = 0,
        .p_align = 0 };
    if (write(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return -1;
    else return 0; }

static int write_trampoline_phdr(int fd, const struct trampoline * tramp) {
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_vaddr = (unsigned long)tramp,
        .p_memsz = tramp->allocated + sizeof(*tramp),
        .p_filesz = tramp->allocated + sizeof(*tramp),
        .p_offset = tramp->landingoffset,
        .p_flags = PF_R | PF_X,
        .p_align = 0 };
    if (write(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return -1;
    else return 0; }

static int write_stack_phdr(int fd) {
    Elf64_Phdr phdr = {
        .p_type = PT_GNU_STACK,
        .p_vaddr = 0,
        .p_memsz = 0,
        .p_filesz = 0,
        .p_offset = 0,
        .p_flags = PF_R,
        .p_align = 0 };
    if (write(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return -1;
    else return 0; }

static int write_brk_phdr(int fd, const struct trampoline * tramp) {
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_vaddr = (unsigned long)tramp->initialbrk - PAGE_SIZE,
        .p_memsz = PAGE_SIZE,
        .p_filesz = 0,
        .p_offset = 0,
        .p_flags = PF_R | PF_W,
        .p_align = 0 };
    if (write(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return -1;
    else return 0; }

static int write_elf_binary(const char * path, struct trampoline * tramp){
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0711);
    if (fd < 0) return -1;
    if (write_ehdr(fd, tramp) < 0) goto fail;
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        if (tramp->mappings[x].path == tramp->procselfexe &&
            write_phdr(fd, &tramp->mappings[x]) < 0) goto fail; }
    if (write_trampoline_phdr(fd, tramp) < 0) goto fail;
    if (write_stack_phdr(fd) < 0) goto fail;
    if (write_brk_phdr(fd, tramp) < 0) goto fail;
    /* Now dump out the actual contents of the phdrs */
    int64_t offset = 0;
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        if (tramp->mappings[x].path != tramp->procselfexe) continue;
        if (offset == 0) {
            if (lseek(fd, tramp->mappings[x].offset, SEEK_SET) < 0) goto fail;
            offset = tramp->mappings[x].offset; }
        else {
            ssize_t r = lseek(fd, 0, SEEK_CUR);
            if (r < 0) goto fail;
            assert(r == offset);
            assert(r == tramp->mappings[x].offset); }
        ssize_t r = write(fd,
                          (const void *)tramp->mappings[x].start,
                          tramp->mappings[x].size);
        if (r != (ssize_t)tramp->mappings[x].size) goto fail;
        offset += r; }
    /* Last thing is the trampoline structure itself. */
    ssize_t sz = tramp->allocated + sizeof(*tramp);
    if (save_registers(&tramp->stash)) {
        /* We just got rehydrated. Let's go. */
        return 0; }
    else {
        /* Final stage of writing down the ELF binary. */
        if (write(fd, tramp, sz) != sz) goto fail;
        close(fd);
        return 1; }
  fail:
    close(fd);
    return -1; }

/* The pointers in the bounce area point at the half-rehydrated stack,
 * which has now been unmapped. All of the data is copied into the
 * bounce area, though, so we can get at it with a fairly simple
 * translation. */
static const void * translate_new_environment(const void * bounce_area,
                                              const void * ptr,
                                              unsigned long rsp) {
    return (const void *)((unsigned long)ptr -
                          rsp +
                          8 +
                          (unsigned long)bounce_area); }

static void extract_new_environment(const void * bounce_area,
                                    struct new_environment * env) {
    unsigned long rsp = ((unsigned long *)bounce_area)[0];
    unsigned long argc = ((unsigned long *)bounce_area)[1];
    const char ** new_argv =
        (const char **)(bounce_area + 2 * sizeof(unsigned long));
    const char ** new_environ = new_argv + argc + 1;
    unsigned nr_environ;
    for (nr_environ = 0; new_environ[nr_environ]; nr_environ++) ;
    if (env) {
        unsigned needed = 0;
        /* argv pointers */
        needed += sizeof(env->argv[0]) * (argc + 1);
        /* environment pointers */
        needed += sizeof(env->environ[0]) * (nr_environ + 1);
        /* argv values */
        for (unsigned x = 0; x < argc; x++) {
            needed += strlen(translate_new_environment(bounce_area,
                                                       new_argv[x],
                                                       rsp)) + 1; }
        /* environ values */
        for (unsigned x = 0; x < nr_environ; x++) {
            needed += strlen(translate_new_environment(bounce_area,
                                                       new_environ[x],
                                                       rsp)) + 1; }
        void * buffer = alloc_with_mmap(needed);
        env->argc = argc;
        env->argv = buffer;
        buffer += sizeof(env->argv[0]) * (argc + 1);
        env->environ = buffer;
        buffer += sizeof(env->environ[0]) * (nr_environ + 1);
        for (unsigned x = 0; x < argc; x++) {
            const char * old = translate_new_environment(bounce_area,
                                                         new_argv[x],
                                                         rsp);
            size_t sz = strlen(old);
            env->argv[x] = buffer;
            memcpy(buffer, old, sz + 1);
            buffer += sz + 1; }
        for (unsigned x = 0; x < nr_environ; x++) {
            const char * old = translate_new_environment(bounce_area,
                                                         new_environ[x],
                                                         rsp);
            size_t sz = strlen(old);
            env->environ[x] = buffer;
            memcpy(buffer, old, sz + 1);
            buffer += sz + 1; } }
    const char * last_env = translate_new_environment(bounce_area,
                                                      new_environ[nr_environ-1],
                                                      rsp);
    const void * bounce_end = last_env + strlen(last_env);
    bounce_end = (void *)(((unsigned long)bounce_end + PAGE_SIZE - 1) &
                          ~(PAGE_SIZE - 1));
    munmap((void *)bounce_area, bounce_end - bounce_area); }

void release_new_environment(struct new_environment * env) {
    if (!env) return;
    else free_with_mmap(env->argv); }

/* unexec() proper. This handles storing memory and registers. */
static int unexec_core(const char * path, struct new_environment * env) {
    int r;
    r = -1;
    struct trampoline * tramp = MAP_FAILED;
    size_t sz = 0;
    char * mappings_str = read_file("/proc/self/maps");
    if (!mappings_str) goto end;
    /* Start with an allocator which can't do anything, even though we
     * know it'll fail, mostly so that that path gets tested. */
    size_t extra_sz = 0;
    while (true) {
        sz = sizeof(*tramp) + extra_sz;
        sz = (sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        /* We need this to be below all other mappings, so that it
         * doesn't affect initial brk, but not so low the kernel stops
         * us mapping it. Guess 16 pages from the bottom is safe. */
        tramp = mmap((void *)(PAGE_SIZE * 16),
                     sz,
                     PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                     -1,
                     0);
        if (tramp == MAP_FAILED) goto end;
        if (extra_sz != 0) tramp->allocated = sz - sizeof(*tramp);
        else tramp->allocated = 0;
        if (parse_mappings(mappings_str, tramp) < 0) goto end;
        if (tramp->used <= tramp->allocated) break;
        /* Guessed too small. */
        extra_sz = tramp->used;
        munmap(tramp, sz); }
    place_phdrs(tramp);
    unsigned long brk = getbrk();
    r = write_elf_binary(path, tramp);
    if (r == 0) {
        unsigned long newbrk = getbrk();
        /* This is error-prone and hard to test elsewhere, so assert on it
         * here. */
        assert(brk == newbrk);
        extract_new_environment((void *)tramp + sz, env); }
    if (r == 1) {
        chmod(path, 0700);
        if (env) memset(env, 0, sizeof(*env)); }
  end:
    free_with_mmap(mappings_str);
    if (tramp != MAP_FAILED) munmap(tramp, sz);
    return r; }

static bool validsignr(int sig) {
    return sig != SIGKILL && sig != SIGSTOP && sig != 32 && sig != 33; }

int unexec(const char * path, struct new_environment * env) {
    long persona;
    persona = personality(0xffffffff);
    if (persona < 0) return -1;
#define NR_SIGS 64
    struct sigaction sigs[64];
    stack_t stack;
    for (int i = 1; i < NR_SIGS; i++) {
        if (validsignr(i) && sigaction(i, NULL, &sigs[i]) < 0) {
            return -1; } }
    if (sigaltstack(NULL, &stack) < 0) return -1;
    int r = unexec_core(path, env);
    if (r == 0) {
        /* XXX not clear if returning an error, with the process
         * half-restored, is the right answer here. Might be cleaner
         * to just abort(). */
        if (personality(persona) < 0) return -1;
        for (int i = 1; i < NR_SIGS; i++) {
            if (validsignr(i) && sigaction(i, &sigs[i], NULL) < 0) {
                return -1; } }
        if (sigaltstack(&stack, NULL) < 0) return -1; }
    return r; }
