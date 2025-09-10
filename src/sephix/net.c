#include "sephix/net.h"
#include "sephix/sandbox.h"
#include "util.h"

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/socket.h>

int
set_link_updown(struct nl_sock *sock, struct rtnl_link *link, int up)
{
	int exit_code = 0;
	int err;
	struct rtnl_link *link_change;

	link_change = rtnl_link_alloc();
	if (link_change == NULL) {
		PERROR("rtnl_link_change");
		_EXIT(out, -1);
	}

	(up ? rtnl_link_set_flags : rtnl_link_unset_flags)(link_change, IFF_UP);
	if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0) {
		LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));
		_EXIT(out_link_change, -1);
	}

out_link_change:
	rtnl_link_put(link_change);
out:
	return exit_code;
}

int
add_addr(struct nl_sock *sock, struct rtnl_link *link, const char *cidr)
{
	int exit_code = 0;
	struct rtnl_addr *addr;
	struct nl_addr *local;
	int ifindex;
	int err;

	addr = rtnl_addr_alloc();
	if (addr == NULL) {
		PERROR("rtnl_addr_alloc");
		_EXIT(out, -1);
	}

	if ((err = nl_addr_parse(cidr, AF_INET, &local)) < 0) {
		LOG_ERROR("nl_addr_parse(%s): %s", cidr, nl_geterror(err));
		_EXIT(out_addr, -1);
	}

	ifindex = rtnl_link_get_ifindex(link);
	if (ifindex <= 0) {
		LOG_ERROR("rtnl_link_get_ifindex");
		_EXIT(out_local, -1);
	}

	rtnl_addr_set_local(addr, local);
	rtnl_addr_set_ifindex(addr, ifindex);

	if ((err = rtnl_addr_add(sock, addr, 0)) < 0) {
		LOG_ERROR("rtnl_addr_add: %s", nl_geterror(err));
		_EXIT(out_local, -1);
	}

out_local:
	nl_addr_put(local);
out_addr:
	rtnl_addr_put(addr);
out:
	return exit_code;
}

int
create_veth(const char *if1, const char *ip1, const char *if2, const char *ip2)
{
	int exit_code = 0;
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *peer;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) {
		PERROR("nl_socket_alloc");
		_EXIT(out, -1);
	}
	if (nl_connect(sock, NETLINK_ROUTE) < 0) {
		PERROR("nl_connect");
		_EXIT(out_sock, -1);
	}

	if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache) < 0) {
		PERROR("rtnl_link_alloc_cache");
		_EXIT(out_sock, -1);
	}

	link = rtnl_link_veth_alloc();
	if (link == NULL) {
		_EXIT(out_link_cache, -1);
	}
	rtnl_link_set_name(link, if1);

	peer = rtnl_link_veth_get_peer(link);
	rtnl_link_set_name(peer, if2);

	if ((err = rtnl_link_add(sock, link, NLM_F_CREATE | NLM_F_EXCL)) < 0) {
		LOG_ERROR("rtnl_link_add: %s", nl_geterror(err));
		_EXIT(out_link, -1);
	}

	if (nl_cache_refill(sock, link_cache) < 0) {
		PERROR("nl_cache_refill");
		_EXIT(out_link, -1);
	}

	struct rtnl_link *l1 = rtnl_link_get_by_name(link_cache, if1);
	if (l1 == NULL) {
		PERROR("rtnl_link_get_by_name");
		_EXIT(out_link, -1);
	}
	struct rtnl_link *l2 = rtnl_link_get_by_name(link_cache, if2);
	if (l2 == NULL) {
		PERROR("rtnl_link_get_by_name");
		_EXIT(out_l1, -1);
	}

	if (ip1 && add_addr(sock, l1, ip1) < 0) {
		LOG_ERROR("add_addr");
		_EXIT(out_l2, -1);
	}
	if (ip2 && add_addr(sock, l2, ip2) < 0) {
		LOG_ERROR("add_addr");
		_EXIT(out_l2, -1);
	}

out_l2:
	rtnl_link_put(l2);
out_l1:
	rtnl_link_put(l1);
out_link:
	rtnl_link_put(link);
out_link_cache:
	nl_cache_free(link_cache);
out_sock:
	nl_socket_free(sock);
out:
	return exit_code;
}

int
move_if_to_ns(const char *ifname, pid_t target_pid)
{
	int exit_code = 0;
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *link_change;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) {
		PERROR("nl_socket_alloc");
		_EXIT(out, -1);
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0) {
		LOG_ERROR("nl_connect: %s", nl_geterror(err));
		_EXIT(out_sock, -1);
	}

	if ((err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0) {
		LOG_ERROR("rtnl_link_alloc_cache: %s", nl_geterror(err));
		_EXIT(out_sock, -1);
	}

	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL) {
		LOG_ERROR("rtnl_link_get_by_name: no such interface %s",
			  ifname);
		_EXIT(out_link_cache, -1);
	}

	link_change = rtnl_link_alloc();
	if (link_change == NULL) {
		PERROR("rtnl_link_alloc");
		_EXIT(out_link, -1);
	}

	rtnl_link_set_ns_pid(link_change, target_pid);
	if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0) {
		LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));
		_EXIT(out_link_change, -1);
	}

out_link_change:
	rtnl_link_put(link_change);
out_link:
	rtnl_link_put(link);
out_link_cache:
	nl_cache_free(link_cache);
out_sock:
	nl_socket_free(sock);
out:
	return exit_code;
}

int
net__set_link_updown(const char *ifname, int up)
{
	int exit_code = 0;
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) {
		PERROR("nl_socket_alloc");
		_EXIT(out, -1);
	}

	if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0) {
		LOG_ERROR("nl_connect: %s", nl_geterror(err));
		_EXIT(out_sock, -1);
	}

	if ((err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0) {
		LOG_ERROR("rtnl_link_alloc_cache: %s", nl_geterror(err));
		_EXIT(out_sock, -1);
	}

	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL) {
		fprintf(stderr, "sephix: no such interface '%s'\n", ifname);
		_EXIT(out_link_cache, -1);
	}

	if (set_link_updown(sock, link, up) < 0) {
		_EXIT(out_link, -1);
	}

out_link:
	rtnl_link_put(link);
out_link_cache:
	nl_cache_free(link_cache);
out_sock:
	nl_socket_free(sock);
out:
	return exit_code;
}

int
net__init(struct sandbox_t *sandbox)
{
	return 0;
}
