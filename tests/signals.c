#include <assert.h>
#include <err.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "unexec.h"

static bool siginted;
static unsigned long rsp;
static void siginthandler(int sig) {
    assert(sig == SIGINT);
    siginted = true;
    asm ( "movq %%rsp, %0" : "=r" (rsp)); }

int main() {
    char template[] = "signalsXXXXXX";
    close(mkstemp(template));
    signal(SIGINT, siginthandler);
    int r = unexec(template);
    if (r < 0) err(1, "unexec %s", template);
    if (r == 1) {
        raise(SIGINT);
        assert(siginted);
        execl(template, template, NULL);
        err(1, "exec"); }
    if (unlink(template) < 0) err(1, "unlink %s", template);
    assert(!siginted);
    raise(SIGINT);
    assert(siginted);
    siginted = false;
    raise(SIGCHLD);
    assert(!siginted);
    stack_t ss = (stack_t){
        .ss_sp = malloc(16384),
        .ss_flags = 0,
        .ss_size = 16384,
    };
    printf("sigstack %p\n", ss.ss_sp);
    if (sigaltstack(&ss, NULL) < 0) err(1, "sigaltstack");
    printf("set sigaltstack\n");
    r = unexec(template);
    if (r < 0) err(1, "unexec2");
    if (r == 1) {
        execl(template, template, NULL);
        err(1, "exec2"); }
    assert(rsp < (unsigned long)ss.ss_sp ||
           rsp >= (unsigned long)ss.ss_sp + ss.ss_size);
    struct sigaction sa = {
        .sa_handler = siginthandler,
        .sa_flags = SA_ONSTACK, };
    if (sigaction(SIGINT, &sa, NULL) < 0) err(1, "sigaction");
    raise(SIGINT);
    printf("rsp %lx, wanted %p,%p\n",
           rsp, ss.ss_sp, ss.ss_sp + ss.ss_size);
    assert(rsp >= (unsigned long)ss.ss_sp);
    assert(rsp < (unsigned long)ss.ss_sp + ss.ss_size);
    if (unlink(template) < 0) err(1, "unlink2 %s", template);
    return 0; }
