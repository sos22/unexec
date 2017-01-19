#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unexec.h"

static void burnstack(int cntr) {
    /* Experimentally determined to be the biggest thing which works
     * pre-fiddling. */
    if (cntr == 7500) return;
    char buf[1024];
    memset(buf, cntr, sizeof(buf));
    unsigned long rsp;
    asm("" : "=r" (rsp) : "m" (buf));
    printf("%05d: %lx\n", cntr, rsp);
    burnstack(cntr + 1);
    asm("" :: "m" (buf)); }

int main() {
    char buf[] = "bigstackXXXXXX";
    close(mkstemp(buf));
    int r = unexec(buf);
    if (r < 0) err(1, "unexec");
    if (r == 0) {
        execl(buf, buf, NULL);
        err(1, "execl %s", buf); }
    burnstack(0);
    unlink(buf);
    return 0; }
