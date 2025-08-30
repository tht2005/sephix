#ifndef __PROFILE_H
#define __PROFILE_H

struct profile_flags_t {
	int unshare_user;
	int unshare_pid;
	int unshare_net;
	int unshare_ipc;
	int unshare_uts;
	int unshare_cgroup;
	int unshare_all;
};

struct profile_command_t {
	int argc;
	char **argv;
};

struct profile_t {
	struct profile_flags_t flags;
	struct profile_command_t *command;
};

int
profile__parse(struct profile_t *profile, char *profile_name);

#endif
