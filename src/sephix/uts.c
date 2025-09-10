#include "util.h"
#include "profile.h"
#include "sephix/sandbox.h"

#include <sched.h>
#include <string.h>
#include <unistd.h>

int
uts__init(struct sandbox_t *sandbox)
{
	int exit_code = 0;
	struct profile_data_t *prof_dt = sandbox->prof_dt;
	char *hostname;
	char *domainname;
	if (sandbox->clone_flags & CLONE_NEWUTS) {
		hostname = prof_dt->hostname;
		if (sethostname(hostname, strlen(hostname)) < 0) {
			PERROR("sethostname");
			_EXIT(out, -1);
		}
		domainname = prof_dt->domainname;
		if (setdomainname(domainname, strlen(domainname)) < 0) {
			PERROR("setdomainname");
			_EXIT(out, -1);
		}
	}
out:
	return exit_code;
}
