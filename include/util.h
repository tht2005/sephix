#ifndef __SEPHIX__UTIL_H
#define __SEPHIX__UTIL_H

#include <errno.h>
#include <string.h> // do not remove
#include <sys/mount.h>

#define LOG_ERROR(fmt, ...) \
	log_error(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
void
log_error(const char *file, int line, const char *func, const char *fmt, ...);
#define PERROR(str) LOG_ERROR("%s: %s", str, strerror(errno))

#define _EXIT(_out, _code)         \
	{                          \
		exit_code = _code; \
		goto _out;         \
	}
#define _ERR_EXIT(_out) _EXIT(_out, EXIT_FAILURE)

/*
 * Conveniently parse option arguments. Example:
 * for --bind <src> <dest>, when argv[i] = "--bind", call
 * PARSE_OPTION(2) => arg[0] = <src>, arg[1] = <dest> and i
 * += 2.
 */
static char *arg[10];  // 10 >= maximum number of arguments of
		       // an option
#define PARSE_OPTION(cnt)                                               \
	{                                                               \
		if (i + cnt >= argc) {                                  \
			fprintf(stderr,                                 \
				"sephix: %s requires %d argument(s)\n", \
				argv[i], cnt);                          \
			goto out;                                       \
		}                                                       \
		for (j = 0; j < cnt; ++j) {                             \
			arg[j] = argv[i + 1 + j];                       \
		}                                                       \
		i += cnt;                                               \
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
