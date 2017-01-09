#ifndef _UNEXEC_H__
#define _UNEXEC_H__

/* Convert the currently running program into an ELF binary.  On
 * success, returns 1 and writes the binary into @path. The binary,
 * when it runs, will look like you did a fork() of the old process in
 * unexec(), except that unexec() will return 0.
 *
 * Returns -1 and sets errno on error.
 */
int unexec(const char * path);

#endif /* !_UNEXEC_H__ */
