#include "sephix/sandbox.h"
#include "syscall_wrappers.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define PERM_RW_R_R 0644

#define PERM_RWX_RX_RX 0755
#define PERM_RWX_RX_RX_STRING "0755"

int
fs__create_public_metadata(struct sandbox_t *sandbox)
{
	int exit_code = 0;
	int fd;
	char *filename = NULL;

	printf("[DEBUG] runtime_dir = %s\n", sandbox->runtime_dir);
	// ensure runtime dir exists
	if (mkdir(sandbox->runtime_dir, PERM_RWX_RX_RX) && errno != EEXIST) {
		PERROR("mkdir");
		_EXIT(out, -1);
	}

	if (mkdir2(sandbox->runtime_dir, "/profile", PERM_RWX_RX_RX) &&
	    errno != EEXIST) {
		PERROR("mkdir");
		_EXIT(out, -1);
	}
	if (asprintf(&filename, "%s/profile/%d", sandbox->runtime_dir,
		     sandbox->master_pid) < 0) {
		PERROR("asprintf");
		_EXIT(out, -1);
	}
	fprintf(stderr, "[DEBUG] filename=%s\n", filename);
	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, PERM_RW_R_R);
	if (fd < 0) {
		PERROR("open");
		_EXIT(out, -1);
	}
	const char *profile_name = "bash\n";  // temporary
	size_t len = strlen(profile_name);
	if (write(fd, profile_name, len) != len) {
		PERROR("write");
		_EXIT(out, -1);
	}
out:
	if (filename) free(filename);
	return exit_code;
}

int
fs__prepare_new_root(struct sandbox_t *sandbox)
{
	if (mkdir2(sandbox->runtime_dir, "/mnt", PERM_RWX_RX_RX) &&
	    errno != EEXIST) {
		PERROR("mkdir");
		return -1;
	}

	if (mount2(NULL, sandbox->runtime_dir, "/mnt", "tmpfs", MS_NOSUID,
		   "mode=755")) {
		PERROR("mount tmpfs");
		return -1;
	}
	if (mount2(NULL, sandbox->runtime_dir, "/mnt", NULL,
		   MS_PRIVATE | MS_REC, NULL)) {
		PERROR("mount private");
		return -1;
	}

	return 0;
}

int
fs__chroot(struct sandbox_t *sandbox)
{
	// Move to sandboxed file system
	if (mkdir2(sandbox->runtime_dir, "/mnt/.old_root", 0755)) {
		PERROR("mkdir");
		return -1;
	}
	if (chdir2(sandbox->runtime_dir, "/mnt") < 0) {
		PERROR("chdir");
		return -1;
	}
	if (pivot_root(".", ".old_root")) {
		PERROR("pivot_root");
		return -1;
	}
	umount2("/.old_root", MNT_DETACH);
	rmdir("/.old_root");
	return 0;
}
