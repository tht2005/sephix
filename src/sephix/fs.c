#include "euid.h"
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

struct clean_public_metadata_t {
	char *profile_filename;
};
void
clean_public_metadata(int status, void *arg)
{
	struct clean_public_metadata_t *clean_info =
		(struct clean_public_metadata_t *)arg;

	unlink(clean_info->profile_filename);

	// TODO: free things, may be this is not neccessary
}

int
fs__create_public_metadata(struct sandbox_t *sandbox)
{
	int fd;
	char *profile_filename = NULL;

	printf("[DEBUG] runtime_dir = %s\n", sandbox->runtime_dir);
	// ensure runtime dir exists
	if (mkdir(sandbox->runtime_dir, PERM_RWX_RX_RX) && errno != EEXIST)
		DIE_PERROR("mkdir");

	if (mkdir2(sandbox->runtime_dir, "/profile", PERM_RWX_RX_RX) &&
	    errno != EEXIST)
		DIE_PERROR("mkdir");
	if (asprintf(&profile_filename, "%s/profile/%d", sandbox->runtime_dir,
		     sandbox->master_pid) < 0)
		DIE_PERROR("asprintf");
	fprintf(stderr, "[DEBUG] profile_filename=%s\n", profile_filename);
	fd = open(profile_filename, O_CREAT | O_WRONLY | O_TRUNC, PERM_RW_R_R);
	if (fd < 0) DIE_PERROR("open");
	const char *profile_name = "bash\n";  // TODO: temporary
	size_t len = strlen(profile_name);
	if (write(fd, profile_name, len) != len) DIE_PERROR("write");

	struct clean_public_metadata_t *clean_info =
		(struct clean_public_metadata_t *)malloc(
			sizeof(struct clean_public_metadata_t));
	if (clean_info == NULL) DIE_PERROR("malloc");
	*clean_info = (struct clean_public_metadata_t){
		.profile_filename = profile_filename,
	};
	if (on_exit(clean_public_metadata, clean_info))
		DIE_LOG_ERROR("on_exit failed");

	return 0;
}

int
fs__prepare_new_root(struct sandbox_t *sandbox)
{
	if (mkdir2(sandbox->runtime_dir, "/mnt", PERM_RWX_RX_RX) &&
	    errno != EEXIST)
		DIE_PERROR("mkdir");

	/*
	 * Mount new "root" with NOSUID option
	 */
	ROOT_PRIVILEGE {
		if (mount2(NULL, sandbox->runtime_dir, "/mnt", "tmpfs", MS_NOSUID, "mode=755"))
			DIE_PERROR("mount tmpfs");
		if (mount2(NULL, sandbox->runtime_dir, "/mnt", NULL, MS_PRIVATE | MS_REC, NULL))
			DIE_PERROR("mount private");
	}
	return 0;
}

int
fs__chroot(struct sandbox_t *sandbox)
{
	EUID__assert_user();
	// Move to sandboxed file system
	if (mkdir2(sandbox->runtime_dir, "/mnt/.old_root", 0755))
		DIE_PERROR("mkdir");
	if (chdir2(sandbox->runtime_dir, "/mnt") < 0)
		DIE_PERROR("chdir");
	ROOT_PRIVILEGE {
		if (pivot_root(".", ".old_root") < 0)
			DIE_PERROR("pivot_root");
		if (umount2("/.old_root", MNT_DETACH) < 0)
			DIE_PERROR("umount2");
		if (rmdir("/.old_root") < 0)
			DIE_PERROR("rmdir");
	}
	return 0;
}
