#include "profile.h"
#include "sephix/sandbox.h"
#include "util.h"

#include <linux/capability.h>
#include <stdio.h>
#include <sys/capability.h>

int
caps_init(struct sandbox_t *sandbox)
{
	int exit_code = 0;
	int i;

	cap_t caps;
	cap_value_t cap;
	cap_flag_value_t cap_flag;
	int ncap;

	struct profile_data_t *prof_dt;
	int *caps_keep;

	caps = cap_get_proc();
	if (caps == NULL) {
		PERROR("cap_get_proc");
		_EXIT(out, -1);
	}

	prof_dt = sandbox->prof_dt;
	ncap = prof_dt->ncap;
	caps_keep = prof_dt->caps_keep;
	for (i = 0; i < ncap; ++i) {
		cap = i;
		cap_flag = caps_keep[i] == 0 ? CAP_CLEAR : CAP_SET;
		if (cap_set_flag(caps, CAP_PERMITTED, 1, &cap, cap_flag) < 0 ||
		    cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, cap_flag) < 0 ||
		    cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR) <
			    0) {
			PERROR("cap_set_flag");
			_EXIT(out, -1);
		}
	}

	if (cap_set_proc(caps) < 0) {
		PERROR("cap_set_proc");
		_EXIT(out, -1);
	}

out:
	if (caps) cap_free(caps);
	return exit_code;
}
