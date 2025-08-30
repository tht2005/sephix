#include "config.h"
#include "confuse.h"
#include "profile.h"
#include "sephix/sandbox.h"
#include "sephix_build_config.h"
#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void
print_usage()
{
	printf("Usage: sephix [OPTIONS] exec <command>\n");
	printf("See 'sephix --help' for all options available.\n");
}

void
print_help()
{
	printf("sephix " SEPHIX_VERSION "\n");
	printf("\n");
	printf("[fixme] sephix is a sandbox program\n");
	printf("\n");
	printf("Usage: sephix [OPTIONS] exec <command>\n");
	printf("\n");
	printf("Options:\n");
	printf("\n");
	printf("	--profile <file_name|profile_name>	Use a custom "
	       "profile\n");
	printf("\n");
}

void
print_version()
{
	printf(SEPHIX_VERSION "\n");
}

int
main(int argc, char **argv)
{
	int exit_code = EXIT_SUCCESS;
	int i, j;

	char *profile_name = NULL;
	char *runtime_dir = NULL;

	int exec_argc = 0;
	char **exec_argv = NULL;

	pid_t child_pid;
	int status;

	struct cfg_t *cfg, *cfg_sec;
	int cli__max_arg_count;
	int cli__max_arg_len;

	struct profile_t profile = { 0 };

	if (config__parse(&cfg, SYSCONF_DIR "/sephix.config") != 0) {
		_ERR_EXIT(out);
	}

	cfg_sec = cfg_getsec(cfg, "cli");
	cli__max_arg_count = cfg_getint(cfg_sec, "max-arg-count");
	cli__max_arg_len = cfg_getint(cfg_sec, "max-arg-len");
	cfg_free(cfg);

	fprintf(stderr, "[DEBUG] cli.max-arg-count = %d\n", cli__max_arg_count);
	fprintf(stderr, "[DEBUG] cli.max-arg-len= %d\n", cli__max_arg_len);

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_help();
			goto out;
		} else if (strcmp(argv[i], "-v") == 0 ||
			   strcmp(argv[i], "--version") == 0) {
			print_version();
			goto out;
		} else if (strcmp(argv[i], "--profile") == 0) {
			PARSE_OPTION(1);
			profile_name = arg[0];

		} else if (strcmp(argv[i], "--unshare-user") == 0) {
		} else if (strcmp(argv[i], "--unshare-user-try") == 0) {
		} else if (strcmp(argv[i], "--unshare-ipc") == 0) {
		} else if (strcmp(argv[i], "--unshare-pid") == 0) {
		} else if (strcmp(argv[i], "--unshare-net") == 0) {
		} else if (strcmp(argv[i], "--unshare-uts") == 0) {
		} else if (strcmp(argv[i], "--unshare-cgroup") == 0) {
		} else if (strcmp(argv[i], "--unshare-cgroup-try") == 0) {
		} else if (strcmp(argv[i], "--unshare-all") == 0) {
		} else if (strcmp(argv[i], "--bind") == 0) {
			PARSE_OPTION(2);

		} else if (strcmp(argv[i], "exec") == 0) {
			goto exec;
		} else {
			if (strncmp(argv[i], "-", 1) == 0 ||
			    strncmp(argv[i], "--", 2) == 0) {
				fprintf(stderr,
					"sephix: %s is an invalid option\n",
					argv[i]);
			} else {
				fprintf(stderr,
					"sephix: %s is an invalid command\n",
					argv[i]);
			}
			_ERR_EXIT(out);
		}

#undef PARSE_OPTION
	}

	// if it reach here, no exec command is parsed
	print_usage();
	_ERR_EXIT(out);

exec:
	assert(profile_name);
	if (profile__parse(&profile, profile_name)) {
		_ERR_EXIT(out);
	}

	exec_argc = argc - 1 - i;
	if (exec_argc > cli__max_arg_count) {
		fprintf(stderr, "[fixme] exec-argc (%d) > max-arg-count (%d)\n",
			exec_argc, cli__max_arg_count);
		_ERR_EXIT(out);
	}
	exec_argv = (char **)malloc((exec_argc + 1) * sizeof(char *));
	if (!exec_argv) {
		PERROR("malloc");
		_ERR_EXIT(out);
	}
	for (j = 0; j < exec_argc; ++j) {
		exec_argv[j] = argv[i + 1 + j];
		if (strlen(exec_argv[j]) > cli__max_arg_len) {
			fprintf(stderr,
				"[fixme] len(exec-argv[j]) (%lu) > max-arg-len "
				"(%d)\n",
				strlen(exec_argv[j]), cli__max_arg_len);
			_ERR_EXIT(out);
		}
	}
	exec_argv[exec_argc] = NULL;

	printf("[DEBUG] exec_argc = %d\n", exec_argc);
	for (i = 0; i <= exec_argc; ++i) {
		printf("[DEBUG] exec_argv[%d] = '%s'\n", i, exec_argv[i]);
	}

	if (getuid() == 0) {
		runtime_dir = strdup("/run/sephix");
		if (!runtime_dir) {
			PERROR("strdup");
			_ERR_EXIT(out);
		}
		printf("[DEBUG] root: runtime_dir = %s\n", runtime_dir);
	} else {
		if (asprintf(&runtime_dir, "/run/user/%d/sephix", getuid()) <
		    0) {
			PERROR("asprintf");
			_ERR_EXIT(out);
		}
		printf("[DEBUG] user: runtime_dir = %s\n", runtime_dir);
	}

	struct sandbox_t sandbox = {
		.pid = getpid(),
		.gid = getgid(),
		.uid = getuid(),
		.name = NULL,
		.runtime_dir = runtime_dir,
		.exec_argc = exec_argc,
		.exec_argv = exec_argv,
	};

	if (sandbox__init(&sandbox)) {
		LOG_ERROR("sandbox__init failed");
		_ERR_EXIT(out);
	}

out:
	if (runtime_dir) free(runtime_dir);
	if (exec_argv) free(exec_argv);
	return exit_code;
}
