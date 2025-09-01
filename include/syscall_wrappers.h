#ifndef __SYSCALL_WRAPPERS_H
#define __SYSCALL_WRAPPERS_H

#include <linux/landlock.h>
#include <stddef.h>
#include <stdint.h>

int
pivot_root(const char *new_root, const char *put_old);

int
landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
			size_t size,
			uint32_t flags);

int
landlock_add_rule(int ruleset_fd,
		  enum landlock_rule_type rule_type,
		  const void *rule_attr,
		  uint32_t flags);

int
landlock_restrict_self(int ruleset_fd, uint32_t flags);

#endif
