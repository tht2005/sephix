#ifndef __SEPHIX__NET_H
#define __SEPHIX__NET_H

#include <netlink/cache.h>
#include <netlink/handlers.h>
#include "sandbox.h"

int
net__set_if_updown(struct sandbox_t *sandbox, const char *ifname, int up);

int
net__link_master_if(struct sandbox_t *sandbox,
		    const char *master_if_name,
		    const char *ip,
		    int default_gw);

#endif
