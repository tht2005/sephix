#ifndef __SEPHIX__SANDBOX_H
#define __SEPHIX__SANDBOX_H

#include <sys/types.h>

struct sandbox_t {
	int clone_flags;

	pid_t pid;
	gid_t gid;
	uid_t uid;

	// variable that store policy profile

	const char *name;
	char *runtime_dir;

	int exec_argc;
	char **exec_argv;
};

int
uts__init(struct sandbox_t *sandbox);

int
net__init(struct sandbox_t *sandbox);

int
fs__prepare_new_root(struct sandbox_t *sandbox);
int
fs__create_public_metadata(struct sandbox_t *sandbox);
int
fs__chroot(struct sandbox_t *sandbox);

int
sandbox__init(struct sandbox_t *sandbox);

#endif
