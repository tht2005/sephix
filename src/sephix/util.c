#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sched.h>
#include <stdio.h>
#include <sys/wait.h>

void
log_error(const char *file, int line, const char *func, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "[ERROR] %s:%d:%s(): ", file, line, func);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

int
unshare_wrapper(int flags)
{
	pid_t child_pid;
	if (unshare(flags)) {
		perror("unshare");
		exit(EXIT_FAILURE);
	}
	if (flags & CLONE_NEWPID) {
		child_pid = fork();
		if (child_pid < 0) {
			perror("fork");
			exit(EXIT_FAILURE);
		}
		if (child_pid > 0) {
			wait(NULL);
			exit(EXIT_SUCCESS);
		}
	}
	// child continues
	return 0;
}
