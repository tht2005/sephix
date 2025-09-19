#ifndef __SEPHIX__NETCTX_H
#define __SEPHIX__NETCTX_H

struct netctx {
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct nl_cache *addr_cache;
	struct nl_cache *route_cache;
};

struct netctx *
netctx__create();

void
netctx__refill_cache(struct netctx *ctx);

void
netctx__free(struct netctx *ctx);

#endif
