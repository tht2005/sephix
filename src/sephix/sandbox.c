#include "sephix/sandbox.h"
#include "sephix/util.h"

#include <linux/prctl.h>
#include <sys/prctl.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int
sandbox__entry(void *arg)
{
	int sig;
	pid_t child_pid;
	int child_status;

	struct sandbox_t *sandbox = (struct sandbox_t *) arg;

	sleep(2);

	printf("Inside new user namespace, uid=%d, gid=%d\n", getuid(), getgid());

	printf ("[DEBUG] %s\n", sandbox->exec_argv[0]);

	if (uts__init(sandbox) < 0) {
		LOG_ERROR("uts__init: error");
		return -1;
	}

	if (fs__prepare_new_root(sandbox) < 0) {
		LOG_ERROR("fs__prepare_new_root: error");
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
		// this should not return unless error
		assert(0);
	}
	else {
		if (waitpid(child_pid, &child_status, 0) < 0) {
			PERROR("waitpid");
			return -1;
		}
		if (WIFEXITED(child_status)) {
			return WEXITSTATUS(child_status);
		}
		else if (WIFSIGNALED(child_status)) {
			sig = WTERMSIG(child_status);
			signal(sig, SIG_DFL);
			kill(getpid(), sig);
		}
		else {
			// weird case
			return 69;
		}
	}
	return 0;
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
	if (fd >= 0)
		close(fd);
	if (path)
		free(path);
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

	if (snprintf(setgroups_path, SETGROUPS_PATH_MAX, "/proc/%ld/setgroups", (long)pid) < 0) {
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
	if (fd >= 0)
		close(fd);
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
	if (map)
		free(map);
	return exit_code;
}

#define STACK_MAX (1 << 15)
char child_stack[STACK_MAX];

int
sandbox__init(struct sandbox_t *sandbox)
{
	int exit_code = 0;

	pid_t child_pid;
	int child_status;

	sandbox->clone_flags = CLONE_NEWNS;

	// [TODO]
	// sandbox->clone_flags |= CLONE_NEWUSER;

	// [TODO]
	sandbox->clone_flags |= CLONE_NEWPID;

	// [TODO]
	sandbox->clone_flags |= CLONE_NEWUTS;

	if (fs__create_public_metadata(sandbox) < 0) {
		LOG_ERROR("fs__create_public_metadata: error");
		_EXIT(out, -1);
	}

	child_pid = clone(sandbox__entry, child_stack + STACK_MAX, sandbox->clone_flags | CLONE_NEWUSER | SIGCHLD, sandbox);
	prctl(PR_SET_PDEATHSIG, SIGKILL); // after parent die, send SIGKILL to child

	if (setup_userns_mapping(sandbox, child_pid) < 0) {
		LOG_ERROR("setup_userns_mapping: error");
		_EXIT(out, -1);
	}

	if (waitpid(child_pid, &child_status, 0) < 0) {
		PERROR("waitpid");
		_EXIT(out, -1);
	}

	if (WIFEXITED(child_status)) {
		fprintf(stderr, "Child exited with code %d\n", WEXITSTATUS(child_status));
	}
	else if (WIFSIGNALED(child_status)) {
		fprintf(stderr, "Child killed with signal %d\n", WTERMSIG(child_status)); 
	}

out:
	return exit_code;
}
