#include "syscall_wrappers.h"
#include "util.h"

#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// clang-format off
static struct landlock_ruleset_attr ruleset_attr = {
	.handled_access_fs =
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |

		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_TRUNCATE |

		LANDLOCK_ACCESS_FS_EXECUTE |
		
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM |

		LANDLOCK_ACCESS_FS_REFER,
	.handled_access_net = 0,
	.scoped = 0,
};
// clang-format on

int
landlock__create_ruleset_fd()
{
	int abi;
	int fd;

	// from https://docs.kernel.org/userspace-api/landlock.html
	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		PERROR("The running kernel does not enable to use Landlock");
		return -1;
	}
	// TODO: add support for abi < 4
	if (abi < 4) {
		fprintf(stderr, "sephix: do not support landlock with abi < 4");
		return -1;
	}
	fprintf(stderr, "[DEBUG] landlock abi = %d\n", abi);
	switch (abi) {
		case 1:
			/* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
			ruleset_attr.handled_access_fs &=
				~LANDLOCK_ACCESS_FS_REFER;
		case 2:
			/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
			ruleset_attr.handled_access_fs &=
				~LANDLOCK_ACCESS_FS_TRUNCATE;
		case 3:
			/* Removes network support for ABI < 4 */
			ruleset_attr.handled_access_net &=
				~(LANDLOCK_ACCESS_NET_BIND_TCP |
				  LANDLOCK_ACCESS_NET_CONNECT_TCP);
		case 4:
			/* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
			ruleset_attr.handled_access_fs &=
				~LANDLOCK_ACCESS_FS_IOCTL_DEV;
		case 5:
			/* Removes LANDLOCK_SCOPE_* for ABI < 6 */
			ruleset_attr.scoped &=
				~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
				  LANDLOCK_SCOPE_SIGNAL);
	}

	fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (fd < 0) {
		PERROR("landlock_create_ruleset");
	}
	return fd;
}

int
landlock__add_path_rule(int ruleset_fd, const char *path, __u64 access)
{
	struct landlock_path_beneath_attr attr = {0};
	int fd;

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		PERROR("open");
		return -1;
	}

	attr.parent_fd = fd;
	attr.allowed_access = access;

	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr,
			      0) < 0) {
		PERROR("landlock_add_rule");
		return -1;
	}

	close(fd);
	return 0;
}

int
landlock__add_path_rule_2(int ruleset_fd,
			  const char *path_prefix,
			  const char *path_suffix,
			  __u64 access)
{
	int status;
	char *path;

	if (asprintf(&path, "%s%s", path_prefix, path_suffix) < 0) {
		PERROR("asprintf");
		return -1;
	}
	status = landlock__add_path_rule(ruleset_fd, path, access);
	free(path);
	return status;
}

int
landlock__apply_ruleset(int ruleset_fd)
{
	if (landlock_restrict_self(ruleset_fd, 0) < 0) {
		PERROR("landlock_restrict_self");
		return -1;
	}
	return 0;
}

int
landlock__parse_perm_flag(__u64 *_access, char c)
{
	__u64 access = 0;
	switch (c) {
		case 'r':
			access |= LANDLOCK_ACCESS_FS_READ_FILE;
			access |= LANDLOCK_ACCESS_FS_READ_DIR;
			break;
		case 'w':
			access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
			access |= LANDLOCK_ACCESS_FS_TRUNCATE;
			access |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
			access |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
			break;
		case 'x':
			access |= LANDLOCK_ACCESS_FS_EXECUTE;
			break;
		case 'c':
			access |= LANDLOCK_ACCESS_FS_MAKE_REG;
			access |= LANDLOCK_ACCESS_FS_MAKE_DIR;
			break;
		case 'C':
			access |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
			access |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
			access |= LANDLOCK_ACCESS_FS_MAKE_SYM;
			access |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
			access |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
			break;
		case 'R':
			access |= LANDLOCK_ACCESS_FS_REFER;
			break;
		default:
			return -1;
	}
	*_access |= access;
	return 0;
}
