#ifndef __SEPHIX__SANDBOX_H
#define __SEPHIX__SANDBOX_H

#include "profile.h"
#include "sephix/netctx.h"

#include <sys/types.h>

struct sandbox_t {
	struct netctx *master_ctx;
	struct netctx *slave_ctx;

	int clone_flags;

	pid_t master_pid;
	pid_t slave_pid;

	uid_t uid;
	gid_t gid;

	struct profile_t *profile;
	struct profile_data_t *prof_dt;

	int master_netns_fd;
	int slave_netns_fd;

	int ruleset_fd;	 // landlock

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

int
seccomp__init(struct sandbox_t *sandbox);

int
caps_init(struct sandbox_t *sandbox);

#endif
