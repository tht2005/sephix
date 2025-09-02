#ifndef __PROFILE_H
#define __PROFILE_H

#if __has_include(<asm-generic/unistd.h>)
#include <asm-generic/unistd.h>
#endif
#ifndef __NR_syscalls
#define __NR_syscalls 1024
#endif

struct profile_t {
	char *filename;
	struct profile_command_list_t *cmd_list;
};

#include "profile_parser.tab.h"	 // must be after profile_t definition

struct profile_data_t {
	int unshare_pid;
	int unshare_net;
	int unshare_ipc;
	int unshare_uts;
	int unshare_cgroup;

	char *hostname;
	char *domainname;

	int syscall_default;
	int syscall_allow[__NR_syscalls];
};
struct profile_data_t *
profile_data_t__create();
void
profile_data_t__free(struct profile_data_t *prof_dt);

struct scanner_extra_t {
	// char strbuf[4096];
};

struct string_list_t {
	int argc;
	int max_argc;
	char **argv;
};
struct profile_command_t {
	const char *filename;
	YYLTYPE loc;
	struct string_list_t *slist;
};
struct profile_command_list_t {
	int count;
	int maxcount;
	struct profile_command_t **cmds;
};

struct string_list_t *
string_list_t__create();
int
string_list_t__add_arg(struct string_list_t *slist, char *arg);

struct profile_command_t *
profile_command_t__create(const char *filename,
			  YYLTYPE loc,
			  struct string_list_t *slist);

struct profile_command_list_t *
profile_command_list_t__create();
int
profile_command_list_t__add_command(struct profile_command_list_t *cmd_list,
				    struct profile_command_t *cmd);
void
profile_command_list_t__free(struct profile_command_list_t *cmd_list);

int
profile__parse(struct profile_t *profile, char *profile_name);

#endif
