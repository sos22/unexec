#ifndef _UNEXEC_H__
#define _UNEXEC_H__

/* argc, argv, and environment of the thing which did the
 * rehydrate. The referenced structures are mostly allocated with
 * malloc(); use release_new_environment() to free them again.*/
struct new_environment {
    int argc;
    char ** argv;
    char ** environ; };

void release_new_environment(struct new_environment *);

/* Convert the currently running program into an ELF binary.  On
 * success, returns 1 and writes the binary into @path. The binary,
 * when it runs, will look like you did a fork() of the old process in
 * unexec(), except that unexec() will return 0.
 *
 * Rehydrate (i.e. when this returns 0) can optionally fill in the new
 * argv and environment in env, which can be NULL if you don't care.
 *
 * Returns -1 and sets errno on error.
 */
int unexec(const char * path, struct new_environment * env);

#endif /* !_UNEXEC_H__ */
