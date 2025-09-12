#include "sephix/sandbox.h"
#include "profile.h"
#include "ds/string.h"
#include "euid.h"
#include "sephix/landlock.h"
#include "sephix/net.h"
#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <glob.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE ((1 << 20) + (1 << 12))

#define PARENT_WAIT_AND_EXIT_AS_CHILD(_pid, _report)                           \
	do {                                                                   \
		int _sig;                                                      \
		int _status;                                                   \
		if (waitpid(_pid, &_status, 0) < 0) {                          \
			PERROR("waitpid");                                     \
			return -1;                                             \
		}                                                              \
		if (_report) {                                                 \
			if (WIFEXITED(_status)) {                              \
				fprintf(stderr, "Child exited with code %d\n", \
					WEXITSTATUS(_status));                 \
			} else if (WIFSIGNALED(_status)) {                     \
				fprintf(stderr,                                \
					"Child killed with signal %d\n",       \
					WTERMSIG(_status));                    \
			}                                                      \
		}                                                              \
		if (WIFEXITED(_status)) {                                      \
			return WEXITSTATUS(_status);                           \
		} else if (WIFSIGNALED(_status)) {                             \
			_sig = WTERMSIG(_status);                              \
			signal(_sig, SIG_DFL);                                 \
			kill(getpid(), _sig);                                  \
		}                                                              \
	} while (0)

enum ACTION {
	ACTION_UNSHARE = 1 << 0,
	ACTION_FS = 1 << 1,
	ACTION_SECCOMP = 1 << 2,
	ACTION_CAPS = 1 << 3,
	ACTION_PERM = 1 << 4,
	ACTION_NET = 1 << 5,

	ACTION_ALL = ((1 << 6) - 1)
};
int
command_interpret(struct profile_command_t *cmd,
		  struct sandbox_t *sandbox,
		  int actions_flags);
int
profile__interpret(struct sandbox_t *sandbox, int actions_flags);

static int pipe_fd[2];	// parent-child sync

int
_ack()
{
	char ch;
	close(pipe_fd[1]);
	if (read(pipe_fd[0], &ch, 1) < 0) {
		PERROR("read");
		return -1;
	}
	close(pipe_fd[0]);
	return 0;
}

int
_trigger()
{
	close(pipe_fd[0]);
	close(pipe_fd[1]);
	return 0;
}

int
sandbox_entry(void *arg)
{
	/*
	 * Parent call clone() with ROOT_PRIVILEGE so the child
	 * inherit it, we need to drop root privilege immediately
	 */
	EUID__user();
	EUID__assert_user();

	int i;
	char ch;

	pid_t child_pid;

	struct sandbox_t *sandbox = (struct sandbox_t *)arg;
	struct profile_data_t *prof_dt = sandbox->prof_dt;

	// wait parent map uid, gid on the new user namespace
	if (_ack() < 0) {
		LOG_ERROR("_ack");
		return -1;
	}

	if (fs__prepare_new_root(sandbox) < 0) {
		LOG_ERROR("fs__prepare_new_root: error");
		return -1;
	}

	sandbox->ruleset_fd = landlock__create_ruleset_fd();
	if (sandbox->ruleset_fd < 0) {
		LOG_ERROR("landlock__create_ruleset_fd");
		return -1;
	}

	if (profile__interpret(sandbox, ACTION_ALL & ~(ACTION_UNSHARE)) < 0) {
		return -1;
	}

	if (uts__init(sandbox) < 0) {
		LOG_ERROR("uts__init: error");
		return -1;
	}

	if (net__init(sandbox) < 0) {
		LOG_ERROR("net__init: error");
		return -1;
	}

	// ipc__init
	if (sandbox->clone_flags & CLONE_NEWIPC) {
		if (mount2("mqueue", sandbox->runtime_dir, "/mnt/dev/mqueue",
			   "mqueue", 0, NULL) < 0) {
			PERROR("mount2");
			return -1;
		}
	}

	if (fs__chroot(sandbox) < 0) {
		LOG_ERROR("fs__chroot: error");
		return -1;
	}

	// filter system calls
	if (seccomp__init(sandbox) < 0) {
		LOG_ERROR("seccomp__init");
		return -1;
	}

	if (caps_init(sandbox) < 0) {
		LOG_ERROR("caps_init");
		return -1;
	}

	// TODO: make an option for no_new_privs?
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		PERROR("set_no_new_privs");
		return -1;
	}

	if (landlock__apply_ruleset(sandbox->ruleset_fd) < 0) {
		PERROR("landlock__apply_ruleset");
		return -1;
	}

	/*
	 * Before switch to user's process, give up root privilege
	 */
	EUID__give_up_root_privilege();
	EUID__assert_user();

	child_pid = fork();
	if (child_pid < 0) {
		PERROR("fork");
		return -1;
	}

	if (child_pid == 0) {
		if (execv(*sandbox->exec_argv, sandbox->exec_argv) < 0) {
			PERROR("execv");
			return -1;
		}
	} else {
		PARENT_WAIT_AND_EXIT_AS_CHILD(child_pid, 0);
	}
	// never reach here
	assert(0);
}

int
write_map(pid_t pid, const char *map, const char *map_file)
{
	char *path = NULL;
	int fd;

	if (asprintf(&path, "/proc/%ld/%s", (long)pid, map_file) < 0)
		DIE_PERROR("asprintf");
	ROOT_PRIVILEGE
	{
		fd = open(path, O_WRONLY);
		if (fd < 0) DIE_PERROR("open");
		if (write(fd, map, strlen(map)) < 0) DIE_PERROR("write");
	}
	close(fd);
	free(path);
	return 0;
}

int
write_uid_map(pid_t pid, const char *map)
{
	return write_map(pid, map, "uid_map");
}

int
write_gid_map(pid_t pid, const char *map)
{
#define SETGROUPS_PATH_MAX 64
	static char setgroups_path[SETGROUPS_PATH_MAX];
	int fd;

	if (snprintf(setgroups_path, SETGROUPS_PATH_MAX, "/proc/%ld/setgroups",
		     (long)pid) < 0) {
		DIE_PERROR("snprintf");
	}

	ROOT_PRIVILEGE
	{
		fd = open(setgroups_path, O_WRONLY);
		if (fd < 0) DIE_PERROR("open");
		if (write(fd, "deny", 4) < 0) DIE_PERROR("write");
	}

	close(fd);
	return write_map(pid, map, "gid_map");
}

int
setup_userns_mapping(struct sandbox_t *sandbox, int child_pid)
{
	char *map = NULL;

	if (asprintf(&map, "0 0 1\n%d %d 1\n", sandbox->uid, sandbox->uid) < 0)
		DIE_PERROR("asprintf");
	if (write_uid_map(child_pid, map) < 0)
		DIE_LOG_ERROR("write_uid_map: error");
	free(map);

	if (asprintf(&map, "0 0 1\n%d %d 1\n", sandbox->gid, sandbox->gid) < 0)
		DIE_PERROR("asprintf");
	if (write_gid_map(child_pid, map) < 0)
		DIE_LOG_ERROR("write_gid_map: error");
	free(map);

	return 0;
}

int
sandbox__init(struct sandbox_t *sandbox)
{
	pid_t child_pid;
	char *child_stack;
	int child_status;
	struct profile_data_t *prof_dt = sandbox->prof_dt;

	if (profile__interpret(sandbox, ACTION_UNSHARE)) return -1;

	sandbox->clone_flags = CLONE_NEWNS | SIGCHLD;
	if (prof_dt->unshare_user) sandbox->clone_flags |= CLONE_NEWUSER;
	if (prof_dt->unshare_pid) sandbox->clone_flags |= CLONE_NEWPID;
	if (prof_dt->unshare_uts) sandbox->clone_flags |= CLONE_NEWUTS;
	if (prof_dt->unshare_ipc) sandbox->clone_flags |= CLONE_NEWIPC;
	if (prof_dt->unshare_net) sandbox->clone_flags |= CLONE_NEWNET;
	if (prof_dt->unshare_cgroup) sandbox->clone_flags |= CLONE_NEWCGROUP;

	if (fs__create_public_metadata(sandbox) < 0)
		DIE_LOG_ERROR("fs__create_public_metadata: error");

	// switch to sandbox_setup
	if (pipe(pipe_fd) < 0) DIE_PERROR("pipe");
	child_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (child_stack == MAP_FAILED) DIE_PERROR("mmap");

	ROOT_PRIVILEGE
	{
		child_pid = clone(sandbox_entry, child_stack + STACK_SIZE,
				  sandbox->clone_flags, sandbox);
	}
	if (child_pid < 0) DIE_PERROR("clone");
	munmap(child_stack, STACK_SIZE);
	prctl(PR_SET_PDEATHSIG,
	      SIGKILL);	 // after parent die, send SIGKILL to child

	// store child's pid
	sandbox->slave_pid = child_pid;

	// map uid, gid in new child's user namespace
	if ((sandbox->clone_flags & CLONE_NEWUSER) &&
	    setup_userns_mapping(sandbox, child_pid) < 0)
		DIE_LOG_ERROR("setup_userns_mapping: error");
	// done writing, signal child
	_trigger();

	PARENT_WAIT_AND_EXIT_AS_CHILD(child_pid, 1);

	return 0;
}

static const char *boolean_true_str[] = {"yes", "on", "y", "true"};
static const char *boolean_false_str[] = {"no", "off", "n", "false"};
int
boolean_value_parse(int *variable, int def, const char *str)
{
	int i;
	if (str) {
		for (i = 0;
		     i < sizeof(boolean_true_str) / sizeof(boolean_true_str[0]);
		     ++i) {
			if (strcmp(str, boolean_true_str[i]) == 0) {
				*variable = 1;
				return 0;
			}
		}
		for (i = 0; i < sizeof(boolean_false_str) /
					sizeof(boolean_false_str[0]);
		     ++i) {
			if (strcmp(str, boolean_false_str[i]) == 0) {
				*variable = 0;
				return 0;
			}
		}
		return -1;
	} else {
		*variable = def;
	}
	return 0;
}

#define MIN_ARGC_GUARD(_min_argc)                                        \
	do {                                                             \
		if (argc < _min_argc) {                                  \
			DIE_CMD_ERROR_1(                                 \
				cmd,                                     \
				"'%s' command do not take less than %d " \
				"argument(s)",                           \
				argv0, _min_argc);                       \
		}                                                        \
	} while (0)
#define MAX_ARGC_GUARD(_max_argc)                                        \
	do {                                                             \
		if (argc > _max_argc) {                                  \
			DIE_CMD_ERROR_1(                                 \
				cmd,                                     \
				"'%s' command do not take more than %d " \
				"argument(s)",                           \
				argv0, _max_argc);                       \
		}                                                        \
	} while (0)
#define ARGC_GUARD(_min_argc, _max_argc)   \
	do {                               \
		MIN_ARGC_GUARD(_min_argc); \
		MAX_ARGC_GUARD(_max_argc); \
	} while (0)

#define SHORT_CMD_SYNTAX_ERROR                        \
	do {                                          \
		DIE_CMD_ERROR_0(cmd, "syntax error"); \
	} while (0)

#define ACTION_FLAGS_GUARD(_out, _flags, _flag)           \
	do {                                              \
		if (((_flags) & (_flag)) == 0) goto _out; \
	} while (0)

char *
get_safeenv(const char *name)
{
	char *value;
	if (strcmp(name, "HOME") == 0) {
		struct passwd *pw;  // must not free this
		pw = getpwuid(getuid());
		if (pw == NULL) DIE_PERROR("getpwuid");
		value = strdup(pw->pw_dir);
		if (value == NULL) DIE_PERROR("strdup");
	} else {
		value = NULL;
	}
	return value;
}

char *
process_argument(struct profile_command_t *cmd, char *arg)
{
	char *p;
	int c;
	int match = 0;

	string str = new_string();
	string tmp;
	char *tmp2;

	for (p = arg; (c = *p); ++p) {
		if (c == match) {
			match = 0;
		} else if (match == 0 && (c == '\'' || c == '\"')) {
			match = c;
		} else {
			if (c == '\\') {
				c = *(++p);
				if (c == '\0')
					DIE_CMD_ERROR_0(
						cmd,
						"escape character '\\' at the "
						"end of argument");
				str = string_push_back(str, c);
			} else if (c == '@' && *(p + 1) == '{') {
				tmp = new_string();
				for (p += 2; *p && *p != '}'; ++p)
					tmp = string_push_back(tmp, *p);
				if (*p == '\0')
					DIE_CMD_ERROR_0(
						cmd, "@{... not ends with '}'");
				tmp2 = get_safeenv(tmp);
				free_string(tmp);
				if (tmp2 == NULL)
					DIE_CMD_ERROR_0(
						cmd,
						"variable @{%s} do not valid\n",
						tmp2);
				str = string_append_back(str, tmp2);
				free(tmp2);
			} else {
				str = string_push_back(str, c);
			}
		}
	}

	tmp2 = strdup(str);
	free_string(str);
	if (tmp2 == NULL) DIE_PERROR("strdup");
	return tmp2;
}

int
command_interpret(struct profile_command_t *cmd,
		  struct sandbox_t *sandbox,
		  int actions_flags)
{
	struct profile_data_t *prof_dt = sandbox->prof_dt;
	int ruleset_fd = sandbox->ruleset_fd;

	int nr;

	int i;
	int argc;
	char *ptr;
	char *argv0, *argv1, *argv2;
	char **argv;

	cap_value_t cap;

	int g_ret;
	int g_flags;
	glob_t g_results;

	char *runtime_dir = sandbox->runtime_dir;
	char *newroot_dir = NULL;
	const char *opt;
	__u64 access;

	if (asprintf(&newroot_dir, "%s/mnt", runtime_dir) < 0)
		DIE_PERROR("asprintf");

	argc = cmd->slist->argc;
	argv = cmd->slist->argv;
	for (i = 0; i < argc; ++i) {
		ptr = process_argument(cmd, argv[i]);
		free(argv[i]);
		argv[i] = ptr;
	}
	assert(argc > 0);
	argv0 = argv[0];
	argv1 = (argc > 1) ? argv[1] : NULL;
	argv2 = (argc > 2) ? argv[2] : NULL;

	if (strcmp(argv0, "unshare-user") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_user, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-pid") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_pid, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-net") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_net, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-ipc") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_ipc, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-uts") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_uts, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-cgroup") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_cgroup, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-all") == 0) {
		MAX_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (boolean_value_parse(&prof_dt->unshare_user, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
		if (boolean_value_parse(&prof_dt->unshare_pid, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
		if (boolean_value_parse(&prof_dt->unshare_net, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
		if (boolean_value_parse(&prof_dt->unshare_ipc, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
		if (boolean_value_parse(&prof_dt->unshare_uts, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
		if (boolean_value_parse(&prof_dt->unshare_cgroup, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "hostname") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (!prof_dt->unshare_uts)
			DIE_CMD_ERROR_0(
				cmd,
				"unshare-uts must be enabled before using "
				"hostname command");
		free(prof_dt->hostname);
		prof_dt->hostname = strdup(argv1);
		if (prof_dt->hostname == NULL) DIE_PERROR("strdup");
	} else if (strcmp(argv0, "domainname") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_UNSHARE);
		if (!prof_dt->unshare_uts)
			DIE_CMD_ERROR_0(
				cmd,
				"unshare-uts must be enabled before using "
				"domainname command");
		free(prof_dt->domainname);
		prof_dt->domainname = strdup(argv1);
		if (prof_dt->domainname == NULL) DIE_PERROR("strdup");
	} else if (strcmp(argv0, "bind") == 0) {
		ARGC_GUARD(3, 3);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_FS);
		if (mount2(argv1, newroot_dir, argv2, NULL, MS_BIND | MS_REC,
			   NULL) < 0)
			DIE_CMD_ERROR_0(cmd, "can not mount '%s' -> '%s': %s\n",
					argv1, argv2, strerror(errno));

	} else if (strcmp(argv0, "mkdir") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_FS);
		ROOT_PRIVILEGE
		{
			if (mkdir2(newroot_dir, argv1, 0755) < 0 && errno != EEXIST)
				DIE_CMD_ERROR_0(cmd, "can not create directory '%s': %s\n", argv1, strerror(errno));
		}
	} else if (strcmp(argv0, "tmpfs") == 0) {
		ARGC_GUARD(2, 3);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_FS);
		if (argc == 2) {
			opt = "size=128M";
		} else {
			opt = argv2;
		}
		if (mount2("tmpfs", newroot_dir, argv1, "tmpfs", 0, opt) < 0)
			DIE_CMD_ERROR_0(cmd, "tmpfs: %s", strerror(errno));
	} else if (strcmp(argv0, "proc") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_FS);
		if (prof_dt->unshare_pid == 0)
			DIE_CMD_ERROR_0(
				cmd,
				"proc: to mount proc file system you must "
				"unshare-pid first");
		if (mount2("proc", newroot_dir, argv1, "proc", 0, NULL) < 0)
			DIE_CMD_ERROR_0(cmd, "proc: %s", strerror(errno));
	} else if (strcmp(argv0, "perm") == 0) {
		MIN_ARGC_GUARD(3);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_PERM);
		access = 0;
		for (ptr = argv1; *ptr; ++ptr) {
			if (landlock__parse_perm_flag(&access, *ptr) < 0) {
				CMD_ERROR_0(cmd,
					    "'perm' command to not support "
					    "'%c' permission flag",
					    *ptr);
			}
		}
		g_flags = 0;
		for (i = 2; i < argc; ++i) {
			g_ret = glob(argv[i], g_flags, NULL, &g_results);
			if (g_ret == GLOB_NOSPACE) {
				DIE_LOG_ERROR("glob: no space");
			} else if (g_ret == GLOB_ABORTED) {
				DIE_LOG_ERROR("glob: aborted");
			} else if (g_ret == GLOB_NOMATCH) {
				DIE("no such file or directory: %s\n", argv[i]);
			}
			g_flags |= GLOB_APPEND;
		}
		for (i = 0; i < g_results.gl_pathc; ++i) {
			if (landlock__add_path_rule_2(ruleset_fd, newroot_dir,
						      g_results.gl_pathv[i],
						      access) < 0)
				DIE_LOG_ERROR("landlock__add_path_rule_2");
		}
		globfree(&g_results);
	} else if (strcmp(argv0, "seccomp.default") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_SECCOMP);
		if (strcmp(argv1, "allow") == 0) {
			prof_dt->syscall_default = SCMP_ACT_ALLOW;
		} else if (strcmp(argv1, "kill") == 0) {
			prof_dt->syscall_default = SCMP_ACT_KILL;
		} else if (strcmp(argv1, "kill-process") == 0) {
			prof_dt->syscall_default = SCMP_ACT_KILL_PROCESS;
		} else {
			CMD_ERROR_0(cmd, "invalid argument %s", argv1);
		}
	} else if (strcmp(argv0, "seccomp.allow") == 0) {
		MIN_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_SECCOMP);
		for (i = 1; i < argc; ++i) {
			nr = seccomp_syscall_resolve_name(argv[i]);
			if (nr == __NR_SCMP_ERROR) {
				DIE_CMD_ERROR_1(cmd, "unknown syscall '%s'",
						argv[i]);
			} else if (nr < 0) {
				DIE_CMD_ERROR_1(cmd,
						"syscall '%s' not supported on "
						"this arch",
						argv[i]);
			} else {
				assert(nr < NUM_SYSCALLS);
				prof_dt->syscall_allow[nr] = 1;
			}
		}
	} else if (strcmp(argv0, "seccomp.deny") == 0) {
		MIN_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_SECCOMP);
		for (i = 1; i < argc; ++i) {
			nr = seccomp_syscall_resolve_name(argv[i]);
			if (nr == __NR_SCMP_ERROR) {
				DIE_CMD_ERROR_1(cmd, "unknown syscall '%s'",
						argv[i]);
			} else if (nr < 0) {
				DIE_CMD_ERROR_1(cmd,
						"syscall '%s' not supported on "
						"this arch",
						argv[i]);
			} else {
				assert(nr < NUM_SYSCALLS);
				prof_dt->syscall_allow[nr] = 0;
			}
		}
	} else if (strcmp(argv0, "caps.drop-all") == 0) {
		ARGC_GUARD(1, 1);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_CAPS);
		memset(prof_dt->caps_keep, 0,
		       prof_dt->ncap * sizeof(prof_dt->caps_keep[0]));
	} else if (strcmp(argv0, "caps.keep") == 0) {
		MIN_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_CAPS);
		for (i = 1; i < argc; ++i) {
			if (cap_from_name(argv[i], &cap) < 0)
				DIE_CMD_ERROR_1(cmd, "unknown capability: %s",
						argv[i]);
			prof_dt->caps_keep[cap] = 1;
		}
	} else if (strcmp(argv0, "caps.drop") == 0) {
		MIN_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_CAPS);
		for (i = 1; i < argc; ++i) {
			if (cap_from_name(argv[i], &cap) < 0)
				DIE_CMD_ERROR_1(cmd, "unknown capability: %s",
						argv[i]);
			prof_dt->caps_keep[cap] = 0;
		}
	} else if (strcmp(argv0, "ifup") == 0) {
		MIN_ARGC_GUARD(2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_NET);
		for (i = 1; i < argc; ++i) {
			if (net__set_link_updown(argv[i], 1) < 0)
				DIE_CMD_ERROR_0(cmd,
						"can't set interface %s up",
						argv[i]);
		}
	} else if (strcmp(argv0, "ifdown") == 0) {
		ARGC_GUARD(2, 2);
		ACTION_FLAGS_GUARD(out, actions_flags, ACTION_NET);
		for (i = 1; i < argc; ++i) {
			if (net__set_link_updown(argv[i], 0) < 0)
				DIE_CMD_ERROR_0(cmd,
						"can't set interface %s down",
						argv[i]);
		}
	} else {
		DIE_CMD_ERROR_0(cmd, "command '%s' do not exists", argv0);
	}

out:
	if (newroot_dir) free(newroot_dir);
	return 0;
}
int
profile__interpret(struct sandbox_t *sandbox, int actions_flags)
{
	int i;
	struct profile_t *profile = sandbox->profile;
	struct profile_data_t *prof_dt = sandbox->prof_dt;
	struct profile_command_list_t *cmd_list;
	struct profile_command_t *cmd;

	if (profile->cmd_list) {
		cmd_list = profile->cmd_list;
		for (i = 0; i < cmd_list->count; ++i) {
			cmd = cmd_list->cmds[i];
			if (command_interpret(cmd, sandbox, actions_flags)) {
				return -1;
			}
		}
	}
	return 0;
}
