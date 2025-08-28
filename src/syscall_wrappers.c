#include "syscall_wrappers.h"

#include <sys/syscall.h>
#include <unistd.h>

int
pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}
