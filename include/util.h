#ifndef __SEPHIX__UTIL_H
#define __SEPHIX__UTIL_H

#include <errno.h>
#include <netlink/errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

// TODO: fix loc error
#define CMD_ERROR_0(_cmd, _fmt, ...)                                          \
	do {                                                                  \
		fprintf(stderr, "file %s, line %d: " _fmt "\n",               \
			_cmd->filename, _cmd->loc.first_line, ##__VA_ARGS__); \
	} while (0)
#define CMD_ERROR_1(_cmd, _fmt, ...)                                       \
	do {                                                               \
		fprintf(stderr, "file %s, line %d, column %d: " _fmt "\n", \
			_cmd->filename, _cmd->loc.first_line,              \
			_cmd->loc.first_column, ##__VA_ARGS__);            \
	} while (0)

#define LOG_ERROR(fmt, ...)                                                  \
	do {                                                                 \
		log_error(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
	} while (0)

#define PERROR(str) LOG_ERROR("%s: %s", str, strerror(errno))

#define PERROR_NETLINK(str, err) LOG_ERROR("%s: %s", str, nl_geterror(err))

#define DIE(_fmt, ...)                                \
	do {                                          \
		fprintf(stderr, _fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE);                   \
	} while (0)
#define DIE_CMD_ERROR_0(_cmd, _fmt, ...)                \
	do {                                            \
		CMD_ERROR_0(_cmd, _fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE);                     \
	} while (0)
#define DIE_CMD_ERROR_1(_cmd, _fmt, ...)                \
	do {                                            \
		CMD_ERROR_1(_cmd, _fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE);                     \
	} while (0)
#define DIE_LOG_ERROR(fmt, ...)                \
	do {                                   \
		LOG_ERROR(fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE);            \
	} while (0)
#define DIE_PERROR(str)             \
	do {                        \
		PERROR(str);        \
		exit(EXIT_FAILURE); \
	} while (0)
#define DIE_PERROR_NETLINK(str, err)      \
	do {                              \
		PERROR_NETLINK(str, err); \
		exit(EXIT_FAILURE);       \
	} while (0)

void
log_error(const char *file, int line, const char *func, const char *fmt, ...);

/*
 * Conveniently parse option arguments. Example:
 * for --bind <src> <dest>, when argv[i] = "--bind", call
 * PARSE_OPTION(2) => arg[0] = <src>, arg[1] = <dest> and i
 * += 2.
 */
static char *arg[10];
#define PARSE_OPTION(cnt)                                                    \
	{                                                                    \
		if (i + cnt >= argc) {                                       \
			DIE("sephix: %s requires %d argument(s)\n", argv[i], \
			    cnt);                                            \
		}                                                            \
		for (j = 0; j < cnt; ++j) {                                  \
			arg[j] = argv[i + 1 + j];                            \
		}                                                            \
		i += cnt;                                                    \
	}

char *
file_read(const char *filename, size_t *out_size);
int
file_write(const char *file, const char *fmt, ...);

int
mkdir2(const char *prefix, const char *suffix, __mode_t mode);

int
mount2(const char *special_file,
       const char *dir_prefix,
       const char *dir_suffix,
       const char *fstype,
       unsigned long rwflag,
       const void *data);
int
chdir2(const char *path_prefix, const char *path_suffix);
int
mknod2(const char *path_prefix,
       const char *path_suffix,
       __mode_t mode,
       __dev_t dev);

#endif
