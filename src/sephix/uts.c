#include <unistd.h>
#include <sched.h>
#include "sephix/sandbox.h"

int
uts__init(struct sandbox_t *sandbox)
{
	int exit_code = 0;
	// [TODO]
	if (sandbox->clone_flags & CLONE_NEWUTS) {
		// sethostname(const char *name, size_t len)
		// setdomainname(const char *name, size_t len)
	}
	return exit_code;
}
