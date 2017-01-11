#include <err.h>
#include <stdio.h>

#include "unexec.h"

int main(int argc, char *argv[]) {
    if (argc != 2) errx(1, "need a single argument, the thing to unexec to");
    int r = unexec(argv[1]);
    if (r == 0) printf("restored\n");
    else if (r == 1) printf("unexeced\n");
    else err(1, "unexec");
    return 0; }
