#include "sephix/sandbox.h"
#include "profile.h"
#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int
profile__interpret(struct profile_t *profile,
		   struct profile_data_t *prof_dt,
		   const char *runtime_dir);

static int pipe_fd[2];	// parent-child sync

int
sandbox_entry(void *arg)
{
	char ch;
	pid_t child_pid;
	struct sandbox_t *sandbox = (struct sandbox_t *)arg;

	if (uts__init(sandbox) < 0) {
		LOG_ERROR("uts__init: error");
		return -1;
	}

	if (net__init(sandbox) < 0) {
		LOG_ERROR("net__init: error");
		return -1;
	}

	if (fs__chroot(sandbox) < 0) {
		LOG_ERROR("fs__chroot: error");
		return -1;
	}

	if ((sandbox->clone_flags & CLONE_NEWUSER) == 0) {
		// [TODO] return to previous user namespace
	}

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
sandbox_setup(void *arg)
{
	int exit_code = 0;
	char ch;

	pid_t child_pid;
	char *child_stack;

	struct sandbox_t *sandbox = (struct sandbox_t *)arg;

	// wait parent map uid, gid on the new user namespace
	close(pipe_fd[1]);
	if (read(pipe_fd[0], &ch, 1) < 0) {
		PERROR("read");
		return -1;
	}
	close(pipe_fd[0]);

	if (fs__prepare_new_root(sandbox) < 0) {
		LOG_ERROR("fs__prepare_new_root: error");
		return -1;
	}

	static struct profile_data_t prof_dt;
	if (profile__interpret(sandbox->profile, &prof_dt,
			       sandbox->runtime_dir)) {
		return -1;
	}

	sandbox->clone_flags = 0;
	// if (prof_dt.unshare_user) sandbox->clone_flags |= CLONE_NEWUSER;
	// if (prof_dt.unshare_pid) sandbox->clone_flags |= CLONE_NEWPID;
	// if (prof_dt.unshare_uts) sandbox->clone_flags |= CLONE_NEWUTS;
	// if (prof_dt.unshare_ipc) sandbox->clone_flags |= CLONE_NEWIPC;
	// if (prof_dt.unshare_net) sandbox->clone_flags |= CLONE_NEWNET;
	// if (prof_dt.unshare_cgroup) sandbox->clone_flags |= CLONE_NEWCGROUP;

	// switch to sandbox_entry
	child_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (child_stack == MAP_FAILED) {
		PERROR("mmap");
		_EXIT(out, -1);
	}
	child_pid = clone(sandbox_entry, child_stack + STACK_SIZE,
			  sandbox->clone_flags | SIGCHLD, sandbox);
	if (child_pid < 0) {
		PERROR("clone");
		_EXIT(out, -1);
	}
	munmap(child_stack, STACK_SIZE);
	prctl(PR_SET_PDEATHSIG,
	      SIGKILL);	 // after parent die, send SIGKILL to child

	PARENT_WAIT_AND_EXIT_AS_CHILD(child_pid, 0);

out:
	return exit_code;
}

int
write_map(pid_t pid, const char *map, const char *map_file)
{
	int exit_code = 0;
	char *path = NULL;

	if (asprintf(&path, "/proc/%ld/%s", (long)pid, map_file) < 0) {
		_EXIT(out, -1);
	}
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		_EXIT(out, -1);
	}
	if (write(fd, map, strlen(map)) < 0) {
		_EXIT(out, -1);
	}

out:
	if (fd >= 0) close(fd);
	if (path) free(path);
	return exit_code;
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
	int exit_code = 0;

	if (snprintf(setgroups_path, SETGROUPS_PATH_MAX, "/proc/%ld/setgroups",
		     (long)pid) < 0) {
		PERROR("snprintf");
		_EXIT(out, -1);
	}
	fd = open(setgroups_path, O_WRONLY);
	if (fd < 0) {
		PERROR("open");
		_EXIT(out, -1);
	}
	if (write(fd, "deny", 4) < 0) {
		PERROR("write");
		_EXIT(out, -1);
	}

out:
	if (fd >= 0) close(fd);
	return (exit_code == 0) ? write_map(pid, map, "gid_map") : exit_code;
}

int
setup_userns_mapping(struct sandbox_t *sandbox, int child_pid)
{
	int exit_code = 0;
	char *map = NULL;

	if (asprintf(&map, "0 %d 1\n", sandbox->uid) < 0) {
		PERROR("asprintf");
		_EXIT(out, -1);
	}
	if (write_uid_map(child_pid, map) < 0) {
		LOG_ERROR("write_uid_map: error");
		_EXIT(out, -1);
	}
	free(map);
	map = NULL;

	if (asprintf(&map, "0 %d 1\n", sandbox->gid) < 0) {
		PERROR("asprintf");
		_EXIT(out, -1);
	}
	if (write_gid_map(child_pid, map) < 0) {
		LOG_ERROR("write_gid_map: error");
		_EXIT(out, -1);
	}
	free(map);
	map = NULL;

out:
	if (map) free(map);
	return exit_code;
}

int
sandbox__init(struct sandbox_t *sandbox)
{
	int exit_code = 0;

	pid_t child_pid;
	char *child_stack;
	int child_status;

	if (fs__create_public_metadata(sandbox) < 0) {
		LOG_ERROR("fs__create_public_metadata: error");
		_EXIT(out, -1);
	}
	// [TODO] parent help child restore user namespace if needed

	// switch to sandbox_setup
	if (pipe(pipe_fd) < 0) {
		PERROR("pipe");
		_EXIT(out, -1);
	}
	child_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (child_stack == MAP_FAILED) {
		PERROR("mmap");
		_EXIT(out, -1);
	}

	child_pid = clone(sandbox_setup, child_stack + STACK_SIZE,
			  CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD, sandbox);
	if (child_pid < 0) {
		PERROR("clone");
		_EXIT(out, -1);
	}
	munmap(child_stack, STACK_SIZE);
	prctl(PR_SET_PDEATHSIG,
	      SIGKILL);	 // after parent die, send SIGKILL to child

	// map uid, gid in new child's user namespace
	if (setup_userns_mapping(sandbox, child_pid) < 0) {
		LOG_ERROR("setup_userns_mapping: error");
		_EXIT(out, -1);
	}
	close(pipe_fd[0]);
	close(pipe_fd[1]);  // done writing, signal child

	PARENT_WAIT_AND_EXIT_AS_CHILD(child_pid, 1);

out:
	return exit_code;
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

#define MIN_ARGC_GUARD(_min_argc)                                          \
	do {                                                               \
		if (argc < _min_argc) {                                    \
			CMD_ERROR_1(cmd,                                   \
				    "%s command do not take less than %d " \
				    "argument(s)",                         \
				    argv0, _min_argc);                     \
			_EXIT(out, -1);                                    \
		}                                                          \
	} while (0)
#define MAX_ARGC_GUARD(_max_argc)                                          \
	do {                                                               \
		if (argc > _max_argc) {                                    \
			CMD_ERROR_1(cmd,                                   \
				    "%s command do not take more than %d " \
				    "argument(s)",                         \
				    argv0, _max_argc);                     \
			_EXIT(out, -1);                                    \
		}                                                          \
	} while (0)
#define ARGC_GUARD(_min_argc, _max_argc)   \
	do {                               \
		MIN_ARGC_GUARD(_min_argc); \
		MAX_ARGC_GUARD(_max_argc); \
	} while (0)

#define SHORT_CMD_SYNTAX_ERROR                    \
	do {                                      \
		CMD_ERROR_0(cmd, "syntax error"); \
		_EXIT(out, -1);                   \
	} while (0)

int
command_interpret(struct profile_command_t *cmd,
		  struct profile_data_t *prof_dt,
		  const char *runtime_dir)
{
	int exit_code = 0;
	int i;
	int argc;
	char *argv0, *argv1, *argv2;
	char **argv;

	char *newroot_dir = NULL;

	if (asprintf(&newroot_dir, "%s/mnt", runtime_dir) < 0) {
		PERROR("asprintf");
		_EXIT(out, -1);
	}

	argc = cmd->slist->argc;
	argv = cmd->slist->argv;
	for (i = 0; i < argc; ++i) {
		// [TODO] process argv[i]...
		// like substitute variable
		// reduce "...", '...', and escaped characters
		// ...
	}
	assert(argc > 0);
	argv0 = argv[0];
	argv1 = (argc > 1) ? argv[1] : NULL;
	argv2 = (argc > 2) ? argv[2] : NULL;

	if (strcmp(argv0, "unshare-user") == 0) {
		MAX_ARGC_GUARD(2);
		if (boolean_value_parse(&prof_dt->unshare_user, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-pid") == 0) {
		if (boolean_value_parse(&prof_dt->unshare_pid, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-net") == 0) {
		MAX_ARGC_GUARD(2);
		if (boolean_value_parse(&prof_dt->unshare_net, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-ipc") == 0) {
		MAX_ARGC_GUARD(2);
		if (boolean_value_parse(&prof_dt->unshare_ipc, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-uts") == 0) {
		MAX_ARGC_GUARD(2);
		if (boolean_value_parse(&prof_dt->unshare_uts, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-cgroup") == 0) {
		MAX_ARGC_GUARD(2);
		if (boolean_value_parse(&prof_dt->unshare_cgroup, 1, argv1))
			SHORT_CMD_SYNTAX_ERROR;
	} else if (strcmp(argv0, "unshare-all") == 0) {
		MAX_ARGC_GUARD(2);
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
	} else if (strcmp(argv0, "bind") == 0) {
		ARGC_GUARD(3, 3);
		if (mount2(argv1, newroot_dir, argv2, NULL, MS_BIND | MS_REC,
			   NULL) < 0) {
			CMD_ERROR_0(cmd, "can not mount '%s' -> '%s': %s\n",
				    argv1, argv2, strerror(errno));
			_EXIT(out, -1);
		}

	} else if (strcmp(argv0, "mkdir") == 0) {
		ARGC_GUARD(2, 2);
		if (mkdir2(newroot_dir, argv1, 0755) < 0 && errno != EEXIST) {
			CMD_ERROR_0(cmd, "can not create directory '%s': %s\n",
				    argv1, strerror(errno));
			_EXIT(out, -1);
		}
	} else {
		CMD_ERROR_0(cmd, "command '%s' do not exists", argv0);
		_EXIT(out, -1);
	}

out:
	if (newroot_dir) free(newroot_dir);
	return exit_code;
}
int
profile__interpret(struct profile_t *profile,
		   struct profile_data_t *prof_dt,
		   const char *runtime_dir)
{
	int i;
	struct profile_command_list_t *cmd_list;
	struct profile_command_t *cmd;

	// default values
	prof_dt->unshare_user = 0;
	prof_dt->unshare_pid = 0;
	prof_dt->unshare_net = 0;
	prof_dt->unshare_ipc = 0;
	prof_dt->unshare_uts = 0;
	prof_dt->unshare_cgroup = 0;

	if (profile->cmd_list) {
		cmd_list = profile->cmd_list;
		for (i = 0; i < cmd_list->count; ++i) {
			cmd = cmd_list->cmds[i];
			if (command_interpret(cmd, prof_dt, runtime_dir)) {
				return -1;
			}
		}
	}
	return 0;
}
