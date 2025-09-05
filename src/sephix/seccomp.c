#include "profile.h"
#include "sephix/sandbox.h"
#include "util.h"

#include <seccomp.h>

int
seccomp__init(struct sandbox_t *sandbox)
{
	int i;
	struct profile_data_t *prof_dt = sandbox->prof_dt;
	int seccomp_default = prof_dt->syscall_default;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(seccomp_default);
	if (ctx == NULL) DIE_PERROR("seccomp_init");

	for (i = 0; i < NUM_SYSCALLS; ++i) {
		switch (prof_dt->syscall_allow[i]) {
			case 0:
				if (seccomp_default != SCMP_ACT_KILL_PROCESS &&
				    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS,
						     i, 0) < 0)
					DIE_PERROR("seccomp_rule_add");
				break;
			case 1:
				if (seccomp_default != SCMP_ACT_ALLOW &&
				    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, i,
						     0) < 0)
					DIE_PERROR("seccomp_rule_add");
				break;
		}
	}

	if (seccomp_load(ctx) < 0) DIE_PERROR("seccomp_load");

	seccomp_release(ctx);
	return 0;
}
