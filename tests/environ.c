#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unexec.h"

int main(int argc, char **argv) {
    char buf[] = "environXXXXXX";
    close(mkstemp(buf));
    struct new_environment env;
    int r = unexec(buf, &env);
    if (r < 0) err(1, "unexec");
    if (r == 1) {
        execl(buf, buf, "hello", NULL);
        err(1, "execl %s", buf); }
    assert(env.argc == 2);
    assert(!strcmp(env.argv[0], buf));
    assert(!strcmp(env.argv[1], "hello"));
    assert(argc == 1);
    assert(argv[1] == NULL);
    release_new_environment(&env);
    setenv("foobly", "moo", 1);
    setenv("wibble", "woo", 1);
    if (unlink(buf) < 0) err(1, "unlink");
    r = unexec(buf, &env);
    if (r < 0) err(1, "unexec");
    if (r == 1) {
        char * args[] = {"buf", NULL};
        char * environ[] = {"foobly=baroom", NULL};
        execve(buf, args, environ);
        err(1, "execve %s", buf); }
    assert(!strcmp(getenv("foobly"), "moo"));
    assert(!strcmp(getenv("wibble"), "woo"));
    assert(!strcmp(env.environ[0], "foobly=baroom"));
    assert(env.environ[1] == NULL);
    release_new_environment(&env);
    if (unlink(buf) < 0) err(1, "unlink");
    return 0; }
