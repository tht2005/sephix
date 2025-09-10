#include "euid.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

// clang-format off
#define UID_UNSET ((uid_t)-1)
#define GID_UNSET ((gid_t)-1)
// clang-format on

uid_t sephix_ruid = UID_UNSET;
gid_t sephix_rgid = GID_UNSET;

#define EUID__GUARD                                                         \
	do {                                                                \
		if (sephix_ruid == UID_UNSET || sephix_rgid == GID_UNSET) { \
			fprintf(stderr, "euid__init is not called!\n");     \
			exit(EXIT_FAILURE);                                 \
		}                                                           \
	} while (0)

void
EUID__print()
{
	EUID__GUARD;
	fprintf(stderr, "sephix_ruid = %d\n", sephix_ruid);
	fprintf(stderr, "sephix_rgid = %d\n", sephix_rgid);
}

void
EUID__assert_user()
{
	EUID__GUARD;
	assert(geteuid() == sephix_ruid);
	assert(getegid() == sephix_rgid);
}

void
EUID__root()
{
	EUID__GUARD;
	seteuid(0);
	setegid(0);
}

void
EUID__user()
{
	EUID__GUARD;
	if (seteuid(sephix_ruid) < 0) {
		DIE_PERROR("seteuid");
		exit(EXIT_FAILURE);  // make sure we exit
	}
	if (setegid(sephix_rgid) < 0) {
		DIE_PERROR("setegid");
		exit(EXIT_FAILURE);  // make sure we exit
	}
}

void
EUID__init()
{
	sephix_ruid = getuid();
	sephix_rgid = getgid();
	EUID__user();  // start as user
}
