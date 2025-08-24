#ifndef __SEPHIX__UTIL_H
#define __SEPHIX__UTIL_H

#include <errno.h>
#include <string.h>

#define LOG_ERROR(fmt, ...) log_error(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
void log_error(const char *file, int line, const char *func, const char *fmt, ...);
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

int
unshare_wrapper(int flags);

#endif
