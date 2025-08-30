#include "profile.h"
#include "ds/string.h"
#include "sephix_build_config.h"
#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int
is_reg_file(const char *filepath)
{
	struct stat st;

	if (stat(filepath, &st) < 0) {
		PERROR("stat");
		return -1;
	}

	if (!S_ISREG(st.st_mode)) {
		return 1;
	}

	return 0;
}

int
get_filepath_from_profile_name(char **_res, const char *profile_name)
{
	int exit_code = 0;
	char *res;
	struct passwd *pw;  // must not free this
	char *usr_filepath_local = NULL;
	char *usr_filepath = NULL;
	char *etc_filepath = NULL;

	if (is_reg_file(profile_name) == 0) {
		res = strdup(profile_name);
		if (res == NULL) {
			PERROR("strdup");
			_EXIT(out, -1);
		}
	} else {
		pw = getpwuid(getuid());
		if (pw == NULL) {
			PERROR("getpwuid");
			_EXIT(out, -1);
		}

		if (asprintf(&usr_filepath_local, "%s/.config/sephix/%s.local",
			     pw->pw_dir, profile_name) < 0) {
			PERROR("asprintf");
			_EXIT(out, -1);
		}
		if (asprintf(&usr_filepath, "%s/.config/sephix/%s.profile",
			     pw->pw_dir, profile_name) < 0) {
			PERROR("asprintf");
			_EXIT(out, -1);
		}
		if (asprintf(&etc_filepath, SYSCONF_DIR "/%s.profile",
			     profile_name) < 0) {
			PERROR("asprintf");
			_EXIT(out, -1);
		}

		if (is_reg_file(usr_filepath_local) == 0) {
			res = usr_filepath_local;
			usr_filepath_local = NULL;
		} else if (is_reg_file(usr_filepath) == 0) {
			res = usr_filepath;
			usr_filepath = NULL;
		} else if (is_reg_file(etc_filepath) == 0) {
			res = etc_filepath;
			etc_filepath = NULL;
		} else {
			fprintf(stderr,
				"sephix: can not find a profile with option "
				"profile='%s'\n",
				profile_name);
			_EXIT(out, -1);
		}
	}
	*_res = res;
out:
	if (usr_filepath_local) free(usr_filepath_local);
	if (usr_filepath) free(usr_filepath);
	if (etc_filepath) free(etc_filepath);
	return exit_code;
}

struct profile_command_t *
profile_command_t__create(int argc, char **argv)
{
	struct profile_command_t *command;
	command = (struct profile_command_t *)malloc(
		sizeof(struct profile_command_t));
	if (command == NULL) {
		PERROR("malloc");
		return NULL;
	}
	command->argc = argc;
	command->argv = argv;
	return command;
}

int
profile__parse(struct profile_t *profile, char *profile_name)
{
	int exit_code = 0;
	char *profile_filepath = NULL;

	char *buf;
	size_t buf_len;

	size_t i;

	int quote;

	string str;

	if (get_filepath_from_profile_name(&profile_filepath, profile_name)) {
		_EXIT(out, -1);
	}
	fprintf(stderr, "[DEBUG] profile_filepath = '%s'\n", profile_filepath);

	buf = file_read(profile_filepath, &buf_len);
	if (!buf) {
		LOG_ERROR("file_read");
		_EXIT(out, -1);
	}

out:
	if (profile_filepath) free(profile_filepath);
	if (buf) free(buf);
	return exit_code;
}
