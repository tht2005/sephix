#include "profile.h"
#include "profile_parser.tab.h"
#include "profile_lexer.h"
#include "sephix_build_config.h"
#include "util.h"

#include <assert.h>
#include <dirent.h>
#include <pwd.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct profile_data_t *
profile_data_t__create()
{
	struct profile_data_t *prof_dt;
	prof_dt =
		(struct profile_data_t *)malloc(sizeof(struct profile_data_t));
	if (prof_dt == NULL) {
		PERROR("malloc");
		return NULL;
	}

	prof_dt->unshare_pid = 0;
	prof_dt->unshare_net = 0;
	prof_dt->unshare_ipc = 0;
	prof_dt->unshare_uts = 0;
	prof_dt->unshare_cgroup = 0;

	prof_dt->hostname = strdup("sephix");
	if (prof_dt->hostname == NULL) {
		PERROR("strdup");
		return NULL;
	}
	prof_dt->domainname = strdup("");
	if (prof_dt->domainname == NULL) {
		PERROR("strdup");
		return NULL;
	}

	// if user do not use seccomp, they'll want this
	prof_dt->syscall_default = SCMP_ACT_ALLOW;
	memset(prof_dt->syscall_allow, -1, sizeof(prof_dt->syscall_allow));

	prof_dt->ncap = cap_max_bits();
	prof_dt->caps_keep = (int *)malloc(prof_dt->ncap * sizeof(int));
	if (prof_dt->caps_keep == NULL) {
		PERROR("malloc");
		return NULL;
	}
	memset(prof_dt->caps_keep, -1, prof_dt->ncap * sizeof(int));

	return prof_dt;
}
void
profile_data_t__free(struct profile_data_t *prof_dt)
{
	free(prof_dt->hostname);
	free(prof_dt->domainname);
	free(prof_dt->caps_keep);
	free(prof_dt);
}

struct string_list_t *
string_list_t__create()
{
	struct string_list_t *cmd;
	cmd = (struct string_list_t *)malloc(sizeof(struct string_list_t));
	if (cmd == NULL) {
		PERROR("malloc");
		return NULL;
	}
	cmd->argc = 0;
	cmd->max_argc = 4;
	cmd->argv = (char **)malloc(cmd->max_argc * sizeof(char *));
	if (cmd->argv == NULL) {
		PERROR("malloc");
		return NULL;
	}
	return cmd;
}
int
string_list_t__add_arg(struct string_list_t *slist, char *arg)
{
	if (slist->argc + 1 > slist->max_argc) {
		slist->argv = (char **)realloc(
			slist->argv, slist->max_argc * 2 * sizeof(char *));
		if (slist->argv == NULL) {
			PERROR("realloc");
			return -1;
		}
		slist->max_argc *= 2;
	}
	slist->argv[slist->argc++] = arg;
	return 0;
}

struct profile_command_t *
profile_command_t__create(const char *filename,
			  YYLTYPE loc,
			  struct string_list_t *slist)
{
	struct profile_command_t *cmd;
	cmd = (struct profile_command_t *)malloc(
		sizeof(struct profile_command_t));
	if (cmd == NULL) {
		PERROR("malloc");
		return NULL;
	}
	cmd->filename = filename;
	cmd->loc = loc;
	cmd->slist = slist;
	return cmd;
}

struct profile_command_list_t *
profile_command_list_t__create()
{
	struct profile_command_list_t *cmd_list;
	cmd_list = (struct profile_command_list_t *)malloc(
		sizeof(struct profile_command_list_t));
	if (cmd_list == NULL) {
		PERROR("malloc");
		return NULL;
	}
	cmd_list->count = 0;
	cmd_list->maxcount = 4;
	cmd_list->cmds = (struct profile_command_t **)malloc(
		cmd_list->maxcount * sizeof(struct profile_command_t *));
	if (cmd_list->cmds == NULL) {
		PERROR("malloc");
		return NULL;
	}
	return cmd_list;
}
int
profile_command_list_t__add_command(struct profile_command_list_t *cmd_list,
				    struct profile_command_t *cmd)
{
	if (cmd_list->count + 1 > cmd_list->maxcount) {
		cmd_list->cmds = (struct profile_command_t **)realloc(
			cmd_list->cmds,
			cmd_list->maxcount * 2 *
				sizeof(struct profile_command_t *));
		if (cmd_list->cmds == NULL) {
			PERROR("realloc");
			return -1;
		}
		cmd_list->maxcount *= 2;
	}
	if (cmd_list->cmds == NULL) {
		PERROR("realloc");
		return -1;
	}
	cmd_list->cmds[cmd_list->count++] = cmd;
	return 0;
}
void
profile_command_list_t__free(struct profile_command_list_t *cmd_list)
{
	int i, j;
	struct profile_command_t *cmd;
	for (i = 0; i < cmd_list->count; ++i) {
		cmd = cmd_list->cmds[i];
		for (j = 0; j < cmd->slist->argc; ++j)
			free(cmd->slist->argv[j]);
		free(cmd->slist->argv);
		free(cmd->slist);
		free(cmd);
	}
	free(cmd_list);
}

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

		if (asprintf(&usr_filepath, "%s/.config/sephix/%s", pw->pw_dir,
			     profile_name) < 0) {
			PERROR("asprintf");
			_EXIT(out, -1);
		}
		if (asprintf(&etc_filepath, SYSCONF_DIR "/%s", profile_name) <
		    0) {
			PERROR("asprintf");
			_EXIT(out, -1);
		}

		if (is_reg_file(usr_filepath) == 0) {
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
	if (usr_filepath) free(usr_filepath);
	if (etc_filepath) free(etc_filepath);
	return exit_code;
}

int
profile__parse(struct profile_t *profile, char *profile_name)
{
	int exit_code = 0;
	int status;
	char *profile_filepath = NULL;

	FILE *f_in;

	yyscan_t scanner = NULL;
	struct scanner_extra_t extra;

	if (get_filepath_from_profile_name(&profile_filepath, profile_name)) {
		_EXIT(out, -1);
	}
	profile->filename = profile_filepath;
	fprintf(stderr, "[DEBUG] profile_filepath = '%s'\n", profile_filepath);

	f_in = fopen(profile_filepath, "r");
	if (!f_in) {
		PERROR("fopen");
		_EXIT(out, -1);
	}

	yylex_init(&scanner);
	yylex_init_extra(&extra, &scanner);
	yyset_in(f_in, scanner);
	if ((status = yyparse(scanner, profile))) {
		LOG_ERROR("yyparse exit %d", status);
		_EXIT(out, -1);
	}

out:
	if (f_in) fclose(f_in);
	if (scanner) yylex_destroy(scanner);
	return exit_code;
}
