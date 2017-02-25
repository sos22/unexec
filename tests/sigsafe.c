#include <sys/time.h>
#include <err.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "unexec.h"

static char path[] = "sigsafeXXXXXX";

static unsigned nr_signals;

static volatile bool signalled;

static double now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6; }

static void sighandler(int ignore __attribute__((unused))) {
    assert(!signalled);
    nr_signals++;
    int r = unexec(path, NULL);
    if (r < 0) err(1, "unexec");
    if (r == 1) {
        execl(path, path, NULL);
        err(1, "execl %s", path); }
    unlink(path);
    signalled = true; }

int main() {
    close(mkstemp(path));
    signal(SIGALRM, sighandler);
    double start = now();
    double last = now();
    while (true) {
        double cntr = now();
        if (cntr - start > 10) break;
        assert(cntr - last < 1);
        printf("iter %d time %f\n", nr_signals, cntr - last);
        last = cntr;
        struct itimerval itimer = {
            .it_interval = {
                .tv_sec = 0,
                .tv_usec = 10000, },
            .it_value = {
                .tv_sec = 0,
                .tv_usec = 10000, } };
        signalled = false;
        if (setitimer(ITIMER_REAL, &itimer, NULL) < 0) err(1, "setitimer");
        while (!signalled) {
            unsigned r = random() % 100000;
            void * ptr = malloc(r);
            free(ptr); } }
    unlink(path);
    return 0; }
