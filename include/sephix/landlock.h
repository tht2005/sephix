#ifndef __SEPHIX__LANDLOCK_H
#define __SEPHIX__LANDLOCK_H

#include <linux/landlock.h>

int
landlock__create_ruleset_fd();

int
landlock__add_path_rule (int ruleset_fd, const char *path, __u64 access);
int
landlock__add_path_rule_2(int ruleset_fd,
			  const char *path_prefix,
			  const char *path_suffix,
			  __u64 access);

int
landlock__apply_ruleset(int ruleset_fd);

#endif
