#include "sephix/config.h"
#include "sephix/sandbox.h"
#include "sephix/util.h"
#include "sephix_config.h"

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
	printf("	--unshare-user			Create a new user "
	       "namespace\n");
	printf("	--unshare-user-try		Create a new user "
	       "namespace if possible else skip it\n");
	printf("	--unshare-ipc			Create a new ipc "
	       "namespace\n");
	printf("	--unshare-pid			Create a new pid "
	       "namespace\n");
	printf("	--unshare-net			Create a new network "
	       "namespace\n");
	printf("	--unshare-uts			Create a new uts "
	       "namespace\n");
	printf("	--unshare-cgroup		Create a new cgroup "
	       "namespace\n");
	printf("	--unshare-cgroup-try		Create a new cgroup "
	       "namespace if possible else skip it\n");
	printf("	--unshare-all			Unshare all possible "
	       "namespaces\n");
	printf("\n");
	printf("	--bind <src> <dest>		Bind-mount the host "
	       "path <src> on <dest>\n");
	printf("	--dev-bind <src> <dest>		Bind-mount the host "
	       "path <src> on <dest>, allowing device access\n");
	printf("	--ro-bind <src> <dest>		Bind-mount the host "
	       "path <src> on <dest>, read only on <dest>\n");
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

	const char *profile_name = NULL;
	const char *profile_filename = NULL;

	int exec_argc = 0;
	char **exec_argv = NULL;

	pid_t child_pid;
	int status;

	char *runtime_dir = NULL;

	fprintf(stderr, "[DEBUG] max-arg-count = %d\n", max_arg_count);
	fprintf(stderr, "[DEBUG] max-arg-len= %d\n", max_arg_len);

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_help();
			goto out;
		} else if (strcmp(argv[i], "-v") == 0 ||
			   strcmp(argv[i], "--version") == 0) {
			print_version();
			goto out;
		}

		else if (strcmp(argv[i], "--profile") == 0) {
			PARSE_OPTION(1);
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

		}

		else if (strcmp(argv[i], "exec") == 0) {
			goto exec;
		}

		else {
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
	exec_argc = argc - 1 - i;
	if (exec_argc > max_arg_count) {
		fprintf(stderr, "[fixme] exec-argc (%d) > max-arg-count (%d)\n",
			exec_argc, max_arg_count);
		_ERR_EXIT(out);
	}
	exec_argv = (char **)malloc((exec_argc + 1) * sizeof(char *));
	if (!exec_argv) {
		PERROR("malloc");
		_ERR_EXIT(out);
	}
	for (j = 0; j < exec_argc; ++j) {
		exec_argv[j] = argv[i + 1 + j];
		if (strlen(exec_argv[j]) > max_arg_len) {
			fprintf(stderr,
				"[fixme] len(exec-argv[j]) (%lu) > max-arg-len "
				"(%d)\n",
				strlen(exec_argv[j]), max_arg_len);
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
