#include "syscall_wrappers.h"

#include <linux/landlock.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

int
pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

int
landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
			size_t size,
			uint32_t flags)
{
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

int
landlock_add_rule(int ruleset_fd,
		  enum landlock_rule_type rule_type,
		  const void *rule_attr,
		  uint32_t flags)
{
	return syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}

int
landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}
