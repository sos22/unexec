#include "unexec.h"

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE 4096

/* A thing which the trampoline is going to have to mmap. */
struct mapping {
    uint64_t start;
    uint64_t size;
    off_t offset;
    unsigned prot;
    unsigned flags;
    /* Special case for half-constructed tables: path == NULL means
     * that we're going to map from the binary we write, but we don't
     * have a phdr assigned yet.*/
    const char * path; };

/* This is the structure which gets persisted into the new binary. It
 * has to contain enough information to restore the contents of memory
 * and registers. It cannot be extended while the result is
 * half-constructed, so we do an iterate of trying different potential
 * sizes. */
struct trampoline {
    unsigned allocated;
    unsigned used;
    /* The thing which actually gets run when we start. */
    void * trampoline;
    /* What is the trampoline actually going to restore? */
    struct mapping * mappings;
    unsigned nrmappings;
    const char * procselfexe; /* dup of /proc/sys/exe into trampoline */
    unsigned char allocator[]; };

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
               tramp->mappings[x].path); } }

static char * read_file(const char * path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t res_sz = 16384;
    char * res = malloc(res_sz);
    while (true) {
        ssize_t sz = read(fd, res, res_sz);
        if (sz < res_sz) {
            close(fd);
            if (sz < 0) {
                free(res);
                return NULL; }
            else {
                res[sz] = '\0';
                return res; } }
        lseek(fd, 0, SEEK_SET);
        res_sz = sz * 2;
        res = realloc(res, res_sz); } }

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
    return NULL; }

/* Parse up the mappings file and figure out what we need to program
 * into the trampoline. */
static int parse_mappings(char * str, struct trampoline * out) {
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
        assert(nrdone < out->nrmappings);
        struct mapping * mapping = &out->mappings[nrdone];
        for (line_end = line_start; *line_end != '\n'; line_end++) {
            assert(*line_end); }
        *line_end = '\0';
        char * cursor;
        mapping->start = strtoul(line_start, &cursor, 16);
        if (*cursor != '-') goto fail;
        cursor++;
        uint64_t end = strtoul(cursor, &cursor, 16);
        if (*cursor != ' ') goto fail;
        mapping->size = end - mapping->start;
        cursor++;
        switch (*cursor) {
        case 'r':
            mapping->prot |= PROT_READ;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'w':
            mapping->prot |= PROT_WRITE;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'x':
            mapping->prot |= PROT_EXEC;
            break;
        case '-': break;
        default: goto fail; }
        cursor++;
        switch (*cursor) {
        case 'p':
            mapping->flags = MAP_PRIVATE;
            break;
        case 's':
            mapping->flags = MAP_SHARED;
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
        if (!strcmp(path, "[stack]")) mapping->flags |= MAP_GROWSDOWN;
        mapping->flags |= MAP_FIXED;
        /* Other things we need to fix up somehow. Options are phdrs
         * and mmaps. */
        /* Phdr is safe for any non-shared mapping. */
        bool can_use_phdr = mapping->flags != MAP_SHARED;
        /* mmap is a bit more tricky: Have to be able to read the
         * file, and if it's private in-memory content needs to
         * match file contents */
        bool can_use_mmap;
        /* No path -> cannot mmap */
        if (strlen(path) == 0) can_use_mmap = false;
        else {
            if (errno) goto fail;
            /* path need to be readable */
            struct stat st;
            if (stat(path, &st) < 0) {
                if (errno != ENOENT) goto fail;
                can_use_mmap = false; }
            else if (!(mapping->prot & PROT_READ)) {
                /* Cannot read map -> assume that mmap is safe */
                can_use_mmap = true; }
            else {
                /* Needs to match backing store. */
                int fd = open(path, O_RDONLY);
                if (fd < 0) goto fail;
                const void * remap = mmap(NULL,
                                          mapping->size,
                                          PROT_READ,
                                          MAP_PRIVATE,
                                          fd,
                                          offset);
                close(fd);
                if (remap == MAP_FAILED) goto fail;
                if (memcmp(remap, (const void *)mapping->start, mapping->size)){
                    can_use_mmap = false; }
                munmap((void *)remap, mapping->size);
                can_use_mmap = true; }
            errno = 0; }
        if (can_use_mmap) {
            /* If we can use an mmap then do it. */
            mapping->offset = offset;
            mapping->path = strdup_in_trampoline(path, out); }
        else if (can_use_phdr) {
            /* phdrs are the default. */ }
        else {
            /* Can't mmap, can't phdr -> we fail */
            goto fail; }
        *line_end = '\n';
        nrdone++; }
    out->nrmappings = nrdone;
    printf("needed %d, had %d\n", out->used, out->allocated);
    if (errno) goto fail;
    return 0;
  fail:
    abort();
    return -1; }

/* Go through the bits which need mmaps of the ELF binary and figure
 * out where we're putting the phdrs for them. */
static void place_phdrs(struct trampoline * tramp) {
    /* Need a phdr for the trampoline itself, which isn't included in
     * the basic mappings list. */
    unsigned nr_phdrs = 1;
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        nr_phdrs += tramp->mappings[x].path == NULL; }
    /* Leave space for headers */
    unsigned offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * nr_phdrs;
    /* Page align */
    offset = (offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    for (unsigned x = 0; x < tramp->nrmappings; x++) {
        if (tramp->mappings[x].path) continue;
        tramp->mappings[x].offset = offset;
        offset += tramp->mappings[x].size;
        tramp->mappings[x].path = tramp->procselfexe; } }

/* How are we going to persist the in-memory state of the process? */
static int _find_mappings(void) {
    char * mappings_str = read_file("/proc/self/maps");
    if (!mappings_str) return -1;
    struct trampoline * tramp;
    /* Start with an allocator which can't do anything, even though we
     * know it'll fail, mostly so that that path gets tested. */
    size_t extra_sz = 0;
    while (true) {
        size_t sz = sizeof(*tramp) + extra_sz;
        sz = (sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        tramp = mmap(NULL,
                     sz,
                     PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS,
                     -1,
                     0);
        if (tramp == MAP_FAILED) return -1;
        if (extra_sz != 0) tramp->allocated = sz - sizeof(*tramp);
        else tramp->allocated = 0;
        if (parse_mappings(mappings_str, tramp) < 0) {
            munmap(tramp, sz);
            free(mappings_str);
            return -1; }
        if (tramp->used <= tramp->allocated) break;
        /* Guessed too small. */
        extra_sz = tramp->used;
        munmap(tramp, sz); }
    place_phdrs(tramp);
    printf("assembled trampoline\n");
    dump_trampoline(tramp);
    free(mappings_str);
    abort(); }

int unexec(const char * path) {
    _find_mappings();
#if 0
    /* Build a trampoline containing almost everything we need, with
     * the exception of registers, which get done right at the end of
     * write_elf_binary(). */
    struct trampoline * trampoline;
    int res = build_trampoline(mappings, &trampoline);
    if (res < 0) {
        release_mappings(mappings);
        return res; }
    if (res == 1) {
        /* We need to write the binary. */
        if (write_elf_binary(trampoline, mappings, path) < 0) res = -1; }
    /* Both sides now need to free the trampoline. */
    if (munmap(trampoline, trampoline->size) < 0) {
        /* This really shouldn't fail. */
        err(1, "munmapping trampoline"); }
    release_mappings(mappings);
    return res;
#endif
}
