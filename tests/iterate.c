#include <sys/stat.h>
#include <sys/time.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "unexec.h"

#define NR_ITERATIONS 1000

static double now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6; }

static void dump_maps(int x) {
    FILE *f = fopen("/proc/self/maps", "r");
    char * lineptr = NULL;
    size_t sz = 0;
    while (getline(&lineptr, &sz, f) >= 0) printf("%d: %s", x, lineptr);
    free(lineptr);
    fclose(f); }

int main() {
    for (unsigned x = 0; x < NR_ITERATIONS; x++) {
        dump_maps(x);
        char template[] = "iterateXXXXXX";
        close(mkstemp(template));
        printf("%d: in %s\n", x, template);
        double start  = now();
        int r = unexec(template);
        if (r < 0) err(1, "unexec");
        if (r == 0) {
            printf("%d: got restored after %f\n", x, now() - start);
            if (unlink(template) < 0) err(1, "unlink %s", template);
            continue; }
        printf("%d: unexec took %f\n", x, now() - start);
        if (chmod(template, 0700) < 0) err(1, "chmod");
        struct stat st;
        if (stat(template, &st) < 0) err(1, "stat %s", template);
        printf("%d: size %zx\n", x, st.st_size);
        execl(template, template, NULL);
        err(1, "execl %s", template); }
    return 0; }
