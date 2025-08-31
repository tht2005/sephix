#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void
log_error(const char *file, int line, const char *func, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "[ERROR] %s:%d:%s(): ", file, line, func);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

char *
file_read(const char *filename, size_t *out_size)
{
	char *buf = NULL;
	FILE *fp;
	long size;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		PERROR("fopen");
		goto out;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		PERROR("fseek");
		goto out;
	}
	size = ftell(fp);
	if (size < 0) {
		PERROR("ftell");
		goto out;
	}
	rewind(fp);
	buf = (char *)malloc((size + 1) * sizeof(char));
	if (!buf) {
		PERROR("malloc");
		goto out;
	}
	if (fread(buf, 1, size, fp) != (unsigned long)size) {
		PERROR("fread");
		free(buf);
		buf = NULL;
		goto out;
	}
	buf[size] = '\0';
	if (out_size) *out_size = size;
out:
	if (fp) fclose(fp);
	return buf;
}

int
file_write(const char *file, const char *fmt, ...)
{
	int fd;
	va_list arg;
	int status;

	fd = open(file, O_WRONLY);
	if (fd < 0) {
		// errno is set
		return -1;
	}
	va_start(arg, fmt);
	status = vdprintf(fd, fmt, arg);
	va_end(arg);
	close(fd);
	return status;
}

int
mkdir2(const char *prefix, const char *suffix, __mode_t mode)
{
	int status;
	char *path;

	assert(prefix);
	assert(suffix);

	if (asprintf(&path, "%s%s", prefix, suffix) < 0) {
		return -1;
	}
	status = mkdir(path, mode);
	free(path);
	return status;
}

int
mount2(const char *special_file,
       const char *dir_prefix,
       const char *dir_suffix,
       const char *fstype,
       unsigned long rwflag,
       const void *data)
{
	int status;
	char *dir;

	assert(dir_prefix);
	assert(dir_suffix);

	if (asprintf(&dir, "%s%s", dir_prefix, dir_suffix) < 0) {
		return -1;
	}
	status = mount(special_file, dir, fstype, rwflag, data);
	free(dir);
	return status;
}

int
chdir2(const char *path_prefix, const char *path_suffix)
{
	int status;
	char *path;

	assert(path_prefix);
	assert(path_suffix);

	if (asprintf(&path, "%s%s", path_prefix, path_suffix) < 0) {
		return -1;
	}
	status = chdir(path);
	free(path);
	return status;
}

int
mknod2(const char *path_prefix,
       const char *path_suffix,
       __mode_t mode,
       __dev_t dev)
{
	int status;
	char *path;

	assert(path_prefix);
	assert(path_suffix);

	if (asprintf(&path, "%s%s", path_prefix, path_suffix) < 0) {
		return -1;
	}
	status = mknod(path, mode, dev);
	free(path);
	return status;
}
