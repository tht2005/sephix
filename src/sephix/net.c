#include "sephix/net.h"
#include "euid.h"
#include "sephix/netctx.h"
#include "sephix/sandbox.h"
#include "util.h"

#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netlink/addr.h>
#include <netlink/attr.h>
#include <netlink/cache.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>
#include "netlink/route/nexthop.h"

struct netctx *
netctx__create()
{
	struct netctx *ctx = (struct netctx *)malloc(sizeof(struct netctx));
	if (ctx == NULL) DIE_PERROR("malloc");

	ctx->sock = nl_socket_alloc();
	if (ctx->sock == NULL) DIE_PERROR("nl_socket_alloc");
	if (nl_connect(ctx->sock, NETLINK_ROUTE) < 0) DIE_PERROR("nl_connect");

	if (rtnl_link_alloc_cache(ctx->sock, AF_UNSPEC, &ctx->link_cache) < 0)
		DIE_PERROR("rtnl_link_alloc_cache");

	if (rtnl_addr_alloc_cache(ctx->sock, &ctx->addr_cache) < 0)
		DIE_PERROR("rtnl_addr_alloc_cache");

	if (rtnl_route_alloc_cache(ctx->sock, AF_UNSPEC, 0, &ctx->route_cache) <
	    0)
		DIE_PERROR("rtnl_route_alloc_cache");

	return ctx;
}
void
netctx__refill_cache(struct netctx *ctx)
{
	if (nl_cache_refill(ctx->sock, ctx->link_cache) < 0)
		DIE_PERROR("nl_cache_refill");
	if (nl_cache_refill(ctx->sock, ctx->addr_cache) < 0)
		DIE_PERROR("nl_cache_refill");
	if (nl_cache_refill(ctx->sock, ctx->route_cache) < 0)
		DIE_PERROR("nl_cache_refill");
}
void
netctx__free(struct netctx *ctx)
{
	nl_cache_free(ctx->link_cache);
	nl_cache_free(ctx->addr_cache);
	nl_cache_free(ctx->route_cache);
	nl_socket_free(ctx->sock);
	free(ctx);
}

/*
 * Track number of veth device created in sandbox for naming purpose
 */
static int nveth = 0;

void
dump_cache(struct nl_cache *cache, FILE *fd)
{
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = fd,
	};
	nl_cache_dump(cache, &params);
}

int
set_link_updown(struct nl_sock *sock, struct rtnl_link *link, int up)
{
	int err;
	struct rtnl_link *link_change;

	link_change = rtnl_link_alloc();
	if (link_change == NULL) DIE_PERROR("rtnl_link_change");

	if (up)
		rtnl_link_set_flags(link_change, IFF_UP);
	else
		rtnl_link_unset_flags(link_change, IFF_UP);

	ROOT_PRIVILEGE
	{
		if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0)
			DIE_LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));
	}

	rtnl_link_put(link_change);
	return 0;
}

int
add_addr(struct netctx *ctx, const char *ifname, const char *cidr)
{
	struct rtnl_link *link;
	struct rtnl_addr *addr;
	struct nl_addr *local;
	int ifindex;
	int err;

	netctx__refill_cache(ctx);

	link = rtnl_link_get_by_name(ctx->link_cache, ifname);
	if (link == NULL)
		DIE_LOG_ERROR(
			"rtnl_link_get_by_name: can not find interface %s",
			ifname);

	addr = rtnl_addr_alloc();
	if (addr == NULL) DIE_PERROR("rtnl_addr_alloc");

	if ((err = nl_addr_parse(cidr, AF_INET, &local)) < 0)
		DIE_LOG_ERROR("nl_addr_parse(%s): %s", cidr, nl_geterror(err));

	ifindex = rtnl_link_get_ifindex(link);
	if (ifindex <= 0) DIE_LOG_ERROR("rtnl_link_get_ifindex");

	rtnl_addr_set_local(addr, local);
	rtnl_addr_set_ifindex(addr, ifindex);

	ROOT_PRIVILEGE
	{
		if ((err = rtnl_addr_add(ctx->sock, addr, 0)) < 0)
			DIE_LOG_ERROR("rtnl_addr_add: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	nl_addr_put(local);
	rtnl_addr_put(addr);
	return 0;
}

struct addr_cb_param_t {
	int ifindex;
	char *ip;
	int ip_valid;
	enum {
		/*
		 * Input: ifindex
		 * Output: ip (must set ip = NULL before)
		 */
		ADDR_CB_ALLOC_IP,
		ADDR_CB_GET_IP,

		/*
		 * Input: ifindex, ip
		 * Output: ip_valid = 0/1 (must set = 0 before)
		 */
		ADDR_CB_CHECK,
	} action;
};
void
addr_cb(struct nl_object *obj, void *arg)
{
	struct addr_cb_param_t *params = (struct addr_cb_param_t *)arg;
	int ifindex = params->ifindex;
	int action = params->action;

	struct rtnl_addr *addr = (struct rtnl_addr *)obj;
	if (addr == NULL) DIE_LOG_ERROR("addr = NULL");

	if (rtnl_addr_get_family(addr) == AF_INET6) return;

	int cur_ifindex = rtnl_addr_get_ifindex(addr);
	if (cur_ifindex != ifindex) return;

	const struct nl_addr *local = rtnl_addr_get_local(addr);
	if (local == NULL) DIE_LOG_ERROR("rtnl_addr_get_local failed");

	if (action == ADDR_CB_ALLOC_IP) {
		struct in_addr *ip4 = nl_addr_get_binary_addr(local);
		int prefix_len = nl_addr_get_prefixlen(local);
		int len = nl_addr_get_len(local);
		int family = nl_addr_get_family(local);

		assert(len == 4);
		assert(family == 2);

	} else if (action == ADDR_CB_GET_IP && params->ip == NULL) {
		char buf[INET_ADDRSTRLEN];
		const void *bin_addr = nl_addr_get_binary_addr(local);
		int family = nl_addr_get_family(local);

		if (inet_ntop(family, bin_addr, buf, sizeof(buf)) == NULL)
			DIE_PERROR("inet_ntop");

		char *ip = strdup(buf);
		if (ip == NULL) DIE_PERROR("strdup");
		params->ip = ip;
	} else if (action == ADDR_CB_CHECK && 1) {
		params->ip_valid = 1;
	}
}

int
get_if_addr(struct netctx *ctx, const char *ifname, char **ip_res)
{
	int ifindex = rtnl_link_name2i(ctx->link_cache, ifname);
	if (ifindex == 0)
		DIE_LOG_ERROR("rtnl_link_name2i: can not find interface %s",
			      ifname);
	struct addr_cb_param_t arg = {
		.ifindex = ifindex,
		.action = ADDR_CB_GET_IP,
		.ip = NULL,
	};
	netctx__refill_cache(ctx);
	nl_cache_foreach(ctx->addr_cache, addr_cb, (void *)&arg);

	char *ip = arg.ip;
	*ip_res = ip;
	return ip ? 0 : -1;
}

int
create_veth(struct netctx *ctx,
	    const char *if1,
	    const char *ip1,
	    const char *if2,
	    const char *ip2)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *peer;
	int err;

	netctx__refill_cache(ctx);

	sock = ctx->sock;
	link_cache = ctx->link_cache;

	link = rtnl_link_veth_alloc();
	if (link == NULL) exit(EXIT_FAILURE);
	rtnl_link_set_name(link, if1);

	peer = rtnl_link_veth_get_peer(link);
	rtnl_link_set_name(peer, if2);

	ROOT_PRIVILEGE
	{
		if ((err = rtnl_link_add(sock, link,
					 NLM_F_CREATE | NLM_F_EXCL)) < 0)
			DIE_LOG_ERROR("rtnl_link_add: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	if (ip1 && add_addr(ctx, if1, ip1) < 0) DIE_LOG_ERROR("add_addr");
	if (ip2 && add_addr(ctx, if2, ip2) < 0) DIE_LOG_ERROR("add_addr");

	rtnl_link_put(link);
	return 0;
}

int
move_if_to_ns(struct netctx *ctx, const char *ifname, int target_netns_fd)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *link_change;
	int err;

	netctx__refill_cache(ctx);

	sock = ctx->sock;
	link_cache = ctx->link_cache;

	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL)
		DIE_LOG_ERROR("rtnl_link_get_by_name: no such interface %s",
			      ifname);

	link_change = rtnl_link_alloc();
	if (link_change == NULL) DIE_PERROR("rtnl_link_alloc");

	rtnl_link_set_ns_fd(link_change, target_netns_fd);
	ROOT_PRIVILEGE
	{
		if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0)
			DIE_LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	rtnl_link_put(link_change);
	rtnl_link_put(link);
	return 0;
}

int
set_master(struct netctx *ctx, const char *slave, const char *master)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *link_change;
	int master_idx, err;

	netctx__refill_cache(ctx);

	sock = ctx->sock;
	link_cache = ctx->link_cache;

	link = rtnl_link_get_by_name(link_cache, slave);
	if (link == NULL)
		DIE_LOG_ERROR("can not find %s in host net namespace", slave);

	master_idx = rtnl_link_name2i(link_cache, master);
	if (master_idx == 0)
		DIE_LOG_ERROR(
			"can not get index of interface %s in host net "
			"namespace",
			master);

	link_change = rtnl_link_alloc();
	if (link_change == NULL) DIE_LOG_ERROR("rtnl_link_alloc failed");

	rtnl_link_set_master(link_change, master_idx);
	ROOT_PRIVILEGE
	{
		if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0)
			DIE_LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	rtnl_link_put(link);
	rtnl_link_put(link_change);
	return 0;
}

int
set_if_updown(struct netctx *ctx, const char *ifname, int up)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link;
	netctx__refill_cache(ctx);
	sock = ctx->sock;
	link_cache = ctx->link_cache;
	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL) DIE("sephix: no such interface '%s'\n", ifname);
	if (set_link_updown(sock, link, up) < 0) exit(EXIT_FAILURE);
	netctx__refill_cache(ctx);
	rtnl_link_put(link);
	return 0;
}

int
create_slave_link_dev(struct netctx *ctx,
		      const char *master,
		      const char *slave,
		      const char *slave_type)
{
	int master_idx;
	struct rtnl_link *link;
	int err;

	netctx__refill_cache(ctx);

	master_idx = rtnl_link_name2i(ctx->link_cache, master);
	if (master_idx == 0)
		DIE_LOG_ERROR(
			"can not get index of interface %s in host net "
			"namespace",
			master);

	link = rtnl_link_alloc();
	if (link == NULL) DIE_LOG_ERROR("rtnl_link_alloc: failed");
	rtnl_link_set_name(link, slave);
	rtnl_link_set_link(link, master_idx);
	rtnl_link_set_type(link, slave_type);

	ROOT_PRIVILEGE
	{
		if ((err = rtnl_link_add(ctx->sock, link,
					 NLM_F_CREATE | NLM_F_EXCL)) < 0)
			DIE_LOG_ERROR("rtnl_link_add: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	rtnl_link_put(link);
	return 0;
}

int
add_gateway(struct netctx *ctx,
	    const char *ifname,
	    const char *dst_str,
	    const char *gw_str,
	    int family)
{
	int ifindex;
	int err;
	struct nl_addr *dst, *gw;
	struct rtnl_route *route;
	struct rtnl_nexthop *nh;

	netctx__refill_cache(ctx);

	ifindex = rtnl_link_name2i(ctx->link_cache, ifname);
	if (ifindex == 0)
		DIE_LOG_ERROR("rtnl_link_name2i: can not find interface %s",
			      ifname);

	if ((err = nl_addr_parse(dst_str, family, &dst)) < 0)
		DIE_LOG_ERROR("nl_addr_parse: %s", nl_geterror(err));
	if ((err = nl_addr_parse(gw_str, family, &gw)) < 0)
		DIE_LOG_ERROR("nl_addr_parse: %s", nl_geterror(err));

	route = rtnl_route_alloc();
	if (route == NULL) DIE_LOG_ERROR("rtnl_route_alloc failed");
	rtnl_route_set_table(route, RT_TABLE_MAIN);
	rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
	rtnl_route_set_protocol(route, RTPROT_BOOT);
	rtnl_route_set_dst(route, dst);

	nh = rtnl_route_nh_alloc();
	if (nh == NULL) DIE_LOG_ERROR("rtnl_route_nh_alloc failed");
	rtnl_route_nh_set_ifindex(nh, ifindex);
	rtnl_route_nh_set_gateway(nh, gw);
	rtnl_route_add_nexthop(route, nh);

	ROOT_PRIVILEGE
	{
		if ((err = rtnl_route_add(ctx->sock, route, 0)) < 0)
			DIE_LOG_ERROR("rtnl_route_add: %s", nl_geterror(err));
	}
	netctx__refill_cache(ctx);

	nl_addr_put(dst);
	nl_addr_put(gw);
	rtnl_route_put(route);
	return 0;
}

int
add_default_gateway(struct netctx *ctx,
		    const char *ifname,
		    int family,
		    const char *gw_str)
{
	const char *dst_str;
	assert(family == AF_INET || family == AF_INET6);
	dst_str = family == AF_INET ? "0.0.0.0/0" : "::/0";
	return add_gateway(ctx, ifname, dst_str, gw_str, family);
}

int
add_default_gateway_2(struct netctx *master_ctx,
		      struct netctx *slave_ctx,
		      const char *master_ifname,
		      const char *slave_ifname,
		      const char *gw_str)
{
	char *master_ip = NULL;
	if (gw_str == NULL) {
		get_if_addr(master_ctx, master_ifname, &master_ip);
		gw_str = master_ip;
	}
	add_default_gateway(slave_ctx, slave_ifname, AF_INET, gw_str);
	if (master_ip) free(master_ip);
	return 0;
}

int
get_default_gateway_for_iface(struct netctx *ctx,
			      const char *ifname,
			      char **result_ptr)
{
	struct nl_object *obj;
	int ifindex;
	int err;

	*result_ptr = NULL;
	netctx__refill_cache(ctx);

	ifindex = rtnl_link_name2i(ctx->link_cache, ifname);
	if (ifindex == 0) return -1;

	for (obj = nl_cache_get_first(ctx->route_cache); obj;
	     obj = nl_cache_get_next(obj)) {
		struct rtnl_route *route = (struct rtnl_route *)obj;
		struct nl_addr *dst = rtnl_route_get_dst(route);

		if (!dst) continue;
		if (nl_addr_get_prefixlen(dst) != 0) continue;
		if (nl_addr_get_family(dst) != AF_INET) continue;

		int i;
		int nh_count = rtnl_route_get_nnexthops(route);
		for (i = 0; i < nh_count; ++i) {
			struct rtnl_nexthop *nh =
				rtnl_route_nexthop_n(route, i);
			if (!nh) continue;
			if (rtnl_route_nh_get_ifindex(nh) != ifindex) continue;
			struct nl_addr *gw = rtnl_route_nh_get_gateway(nh);
			if (gw) {
				char buf[INET_ADDRSTRLEN];
				nl_addr2str(gw, buf, sizeof(buf));
				char *ptr = strdup(buf);
				if (ptr == NULL) DIE_PERROR("strdup");
				*result_ptr = ptr;
			}
		}
	}

	return 0;
}

int
net__set_if_updown(struct sandbox_t *sandbox, const char *ifname, int up)
{
	struct netctx *ctx;
	ctx = sandbox->slave_ctx;
	set_if_updown(ctx, ifname, up);
	return 0;
}

int
link_master_if_bridge(struct sandbox_t *sandbox,
		      struct netctx *master_ctx,
		      struct netctx *slave_ctx,
		      const char *master_ifname,
		      const char *ip,
		      int default_gw)
{
	char *master_veth_name;
	char *slave_veth_name;

	if (asprintf(&master_veth_name, "sp%d_eth%d", sandbox->master_pid,
		     nveth) < 0)
		DIE_PERROR("asprintf");
	if (asprintf(&slave_veth_name, "eth%d", nveth) < 0)
		DIE_PERROR("asprintf");
	++nveth;

	create_veth(slave_ctx, master_veth_name, NULL, slave_veth_name, ip);
	move_if_to_ns(slave_ctx, master_veth_name, sandbox->master_netns_fd);
	set_master(master_ctx, master_veth_name, master_ifname);
	set_if_updown(master_ctx, master_veth_name, 1);
	set_if_updown(slave_ctx, slave_veth_name, 1);

	if (default_gw) {
		add_default_gateway_2(master_ctx, slave_ctx, master_ifname,
				      slave_veth_name, NULL);
	}

	free(master_veth_name);
	free(slave_veth_name);
	return 0;
}

int
link_master_if_tun(struct sandbox_t *sandbox,
		   struct netctx *master_ctx,
		   struct netctx *slave_ctx,
		   const char *master_ifname,
		   const char *ip)
{
	char *slave_ifname;
	if (asprintf(&slave_ifname, "eth%d-%d", nveth++, sandbox->master_pid) <
	    0)
		DIE_PERROR("asprintf");
	create_slave_link_dev(master_ctx, master_ifname, slave_ifname,
			      "macvlan");
	move_if_to_ns(master_ctx, slave_ifname, sandbox->slave_netns_fd);
	set_if_updown(slave_ctx, slave_ifname, 1);
	add_addr(slave_ctx, slave_ifname, ip);
	free(slave_ifname);
	return 0;
}

int
link_master_if_eth(struct sandbox_t *sandbox,
		   struct netctx *master_ctx,
		   struct netctx *slave_ctx,
		   const char *master_ifname,
		   const char *ip,
		   int default_gw)
{
	char *slave_ifname;
	if (asprintf(&slave_ifname, "eth%d-%d", nveth++, sandbox->master_pid) <
	    0)
		DIE_PERROR("asprintf");
	create_slave_link_dev(master_ctx, master_ifname, slave_ifname,
			      "macvlan");
	// TODO: may be try ipvlan if above command is not success
	move_if_to_ns(master_ctx, slave_ifname, sandbox->slave_netns_fd);
	set_if_updown(slave_ctx, slave_ifname, 1);
	add_addr(slave_ctx, slave_ifname, ip);
	if (default_gw) {
		char *gw;
		get_default_gateway_for_iface(sandbox->master_ctx,
					      master_ifname, &gw);
		add_default_gateway_2(master_ctx, slave_ctx, master_ifname,
				      slave_ifname, gw);
		free(gw);
	}
	free(slave_ifname);
	return 0;
}

int
net__link_master_if(struct sandbox_t *sandbox,
		    const char *master_ifname,
		    const char *ip,
		    int default_gw)
{
	struct netctx *master_ctx;
	struct netctx *slave_ctx;

	struct rtnl_link *link;

	master_ctx = sandbox->master_ctx;
	slave_ctx = sandbox->slave_ctx;

	link = rtnl_link_get_by_name(master_ctx->link_cache, master_ifname);
	if (link == NULL)
		DIE_LOG_ERROR("rtnl_link_get_by_name: can not find device '%s'",
			      master_ifname);

	if (ip == NULL) {
		// generated an ip address
	} else {
		// check if assigned ip address is valid for device's network
	}

	const char *type = rtnl_link_get_type(link);
	if (type && strcmp(type, "bridge") == 0) {
		link_master_if_bridge(sandbox, master_ctx, slave_ctx,
				      master_ifname, ip, default_gw);
	} else if (type && strcmp(type, "tun") == 0) {
		link_master_if_tun(sandbox, master_ctx, slave_ctx,
				   master_ifname, ip);
	} else {
		switch (rtnl_link_get_arptype(link)) {
			case ARPHRD_LOOPBACK:
				fprintf(stderr,
					"Error: can not link to lo device\n");
				exit(EXIT_FAILURE);
			case ARPHRD_ETHER:
				link_master_if_eth(sandbox, master_ctx,
						   slave_ctx, master_ifname, ip,
						   default_gw);
				break;
			default:
				fprintf(stderr,
					"Error: can not link to %s device, "
					"type do not supported\n",
					master_ifname);
				exit(EXIT_FAILURE);
		}
	}

	return 0;
}

int
net__init(struct sandbox_t *sandbox)
{
	return 0;
}
