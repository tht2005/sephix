#include "sephix_config.h"
#include "sephix/sandbox.h"
#include "sephix/util.h"
#include "syscall_wrappers.h"

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
fs__create_metadata_interface()
{
	int exit_code = EXIT_SUCCESS;
	int fd;
	pid_t pid;
	char *filename = NULL;

	if (mkdir(SEPHIX_RUNTIME_DIR "/profile", PERM_RWX_RX_RX) && errno != EEXIST) {
		PERROR("mkdir");
		_ERR_EXIT(out);
	}
	pid = getpid();
	if (asprintf(&filename, SEPHIX_RUNTIME_DIR "/profile/%d", pid) < 0) {
		LOG_ERROR("asprintf failed");
		_ERR_EXIT(out);
	}
	fprintf(stderr, "[DEBUG] filename=%s\n", filename);
	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, PERM_RW_R_R);
	if (fd < 0) {
		PERROR("open");
		_ERR_EXIT(out);
	}
	const char *profile_name = "bash\n";  // temporary
	size_t len = strlen(profile_name);
	if (write(fd, profile_name, len) != len) {
		PERROR("write");
		_ERR_EXIT(out);
	}
out:
	if (filename) free(filename);
	return exit_code;
}

int
fs__init()
{
	if (mkdir(SEPHIX_RUNTIME_DIR, PERM_RWX_RX_RX) && errno != EEXIST) {
		PERROR("mkdir");
		return -1;
	}

	if (fs__create_metadata_interface()) {
		LOG_ERROR("fs__create_metadata_interface failed");
		return -1;
	}

	unshare_wrapper(CLONE_NEWNS | CLONE_FILES);

	if (mkdir(SEPHIX_RUNTIME_DIR "/mnt", PERM_RWX_RX_RX) && errno != EEXIST) {
		PERROR("mkdir");
		return -1;
	}

	if (mount(NULL, SEPHIX_RUNTIME_DIR "/mnt", "tmpfs", MS_NOSUID,
		  "mode=755")) {
		PERROR("mount tmpfs");
		return -1;
	}
	if (mount(NULL, SEPHIX_RUNTIME_DIR "/mnt", NULL, MS_PRIVATE | MS_REC,
		  NULL)) {
		PERROR("mount private");
		return -1;
	}

	// [fixme] test bash, in future read config and bind
	mkdir(SEPHIX_RUNTIME_DIR "/mnt/proc", 0755);
	mount("proc", SEPHIX_RUNTIME_DIR "/mnt/proc", "proc", 0, NULL);

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/dev", 0755);
	mount("tmpfs", SEPHIX_RUNTIME_DIR "/mnt/dev", "tmpfs",
	      MS_NOSUID | MS_STRICTATIME, "mode=755");
	mknod(SEPHIX_RUNTIME_DIR "/mnt/dev/null", S_IFCHR | 0666,
	      makedev(1, 3));
	mknod(SEPHIX_RUNTIME_DIR "/mnt/dev/zero", S_IFCHR | 0666,
	      makedev(1, 5));
	mknod(SEPHIX_RUNTIME_DIR "/mnt/dev/tty", S_IFCHR | 0666, makedev(5, 0));
	mknod(SEPHIX_RUNTIME_DIR "/mnt/dev/random", S_IFCHR | 0666,
	      makedev(1, 8));

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/usr", 0755);
	mount("/usr", SEPHIX_RUNTIME_DIR "/mnt/usr", NULL, MS_BIND | MS_REC,
	      NULL);

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/bin", 0755);
	mount("/bin", SEPHIX_RUNTIME_DIR "/mnt/bin", NULL, MS_BIND | MS_REC,
	      NULL);

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/opt", 0755);
	mount("/opt", SEPHIX_RUNTIME_DIR "/mnt/opt", NULL, MS_BIND | MS_REC,
	      NULL);

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/etc", 0755);
	mount("/etc", SEPHIX_RUNTIME_DIR "/mnt/etc", NULL, MS_BIND | MS_REC,
	      NULL);

	mkdir(SEPHIX_RUNTIME_DIR "/mnt/lib", 0755);
	mkdir(SEPHIX_RUNTIME_DIR "/mnt/lib64", 0755);
	mount("/lib", SEPHIX_RUNTIME_DIR "/mnt/lib", NULL, MS_BIND | MS_REC,
	      NULL);
	mount("/lib64", SEPHIX_RUNTIME_DIR "/mnt/lib64", NULL, MS_BIND | MS_REC,
	      NULL);

	// Move to sandboxed file system
	if (mkdir(SEPHIX_RUNTIME_DIR "/mnt/.old_root", 0755)) {
		PERROR("mkdir");
		return -1;
	}
	chdir(SEPHIX_RUNTIME_DIR "/mnt");
	if (pivot_root(".", ".old_root")) {
		PERROR("pivot_root");
		return -1;
	}
	umount2("/.old_root", MNT_DETACH);
	rmdir("/.old_root");
	return 0;
}
