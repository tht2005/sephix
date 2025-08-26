#include "config.h"
#include "confuse.h"
#include "util.h"

#include <assert.h>
#include <stddef.h>

static struct cfg_opt_t cli_opts[] = {
	CFG_INT("max-arg-count", 256, CFGF_NONE),
	CFG_INT("max-arg-len", 4096, CFGF_NONE),
	CFG_END()
};

static struct cfg_opt_t opts[] = {
	CFG_SEC("cli", cli_opts, CFGF_NONE),
	CFG_END()
};

int
config__parse(struct cfg_t **_cfg, char *filename)
{
	struct cfg_t *cfg;

	cfg = cfg_init(opts, CFGF_NONE);
	if (cfg_parse(cfg, filename) == CFG_PARSE_ERROR) {
		LOG_ERROR("cfg_parse: failed");
		return 1;
	}

	*_cfg = cfg;
	return 0;
}

