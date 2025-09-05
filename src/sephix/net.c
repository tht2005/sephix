#include "sephix/net.h"
#include "sephix/sandbox.h"
#include "util.h"

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sched.h>
#include <stdlib.h>
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
	int err;
	struct rtnl_link *link_change;

	link_change = rtnl_link_alloc();
	if (link_change == NULL) DIE_PERROR("rtnl_link_change");

	(up ? rtnl_link_set_flags : rtnl_link_unset_flags)(link_change, IFF_UP);
	if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0)
		DIE_LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));

	rtnl_link_put(link_change);
	return 0;
}

int
add_addr(struct nl_sock *sock, struct rtnl_link *link, const char *cidr)
{
	struct rtnl_addr *addr;
	struct nl_addr *local;
	int ifindex;
	int err;

	addr = rtnl_addr_alloc();
	if (addr == NULL) DIE_PERROR("rtnl_addr_alloc");

	if ((err = nl_addr_parse(cidr, AF_INET, &local)) < 0)
		DIE_LOG_ERROR("nl_addr_parse(%s): %s", cidr, nl_geterror(err));

	ifindex = rtnl_link_get_ifindex(link);
	if (ifindex <= 0) DIE_LOG_ERROR("rtnl_link_get_ifindex");

	rtnl_addr_set_local(addr, local);
	rtnl_addr_set_ifindex(addr, ifindex);

	if ((err = rtnl_addr_add(sock, addr, 0)) < 0)
		DIE_LOG_ERROR("rtnl_addr_add: %s", nl_geterror(err));

	nl_addr_put(local);
	rtnl_addr_put(addr);
	return 0;
}

int
create_veth(const char *if1, const char *ip1, const char *if2, const char *ip2)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *peer;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) DIE_PERROR("nl_socket_alloc");
	if (nl_connect(sock, NETLINK_ROUTE) < 0) DIE_PERROR("nl_connect");

	if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache) < 0)
		DIE_PERROR("rtnl_link_alloc_cache");

	link = rtnl_link_veth_alloc();
	if (link == NULL) exit(EXIT_FAILURE);
	rtnl_link_set_name(link, if1);

	peer = rtnl_link_veth_get_peer(link);
	rtnl_link_set_name(peer, if2);

	if ((err = rtnl_link_add(sock, link, NLM_F_CREATE | NLM_F_EXCL)) < 0)
		DIE_LOG_ERROR("rtnl_link_add: %s", nl_geterror(err));

	if (nl_cache_refill(sock, link_cache) < 0)
		DIE_PERROR("nl_cache_refill");

	struct rtnl_link *l1 = rtnl_link_get_by_name(link_cache, if1);
	if (l1 == NULL) DIE_PERROR("rtnl_link_get_by_name");
	struct rtnl_link *l2 = rtnl_link_get_by_name(link_cache, if2);
	if (l2 == NULL) DIE_PERROR("rtnl_link_get_by_name");

	if (ip1 && add_addr(sock, l1, ip1) < 0) DIE_LOG_ERROR("add_addr");
	if (ip2 && add_addr(sock, l2, ip2) < 0) DIE_LOG_ERROR("add_addr");

	rtnl_link_put(l2);
	rtnl_link_put(l1);
	rtnl_link_put(link);
	nl_cache_free(link_cache);
	nl_socket_free(sock);
	return 0;
}

int
move_if_to_ns(const char *ifname, pid_t target_pid)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link, *link_change;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) DIE_PERROR("nl_socket_alloc");
	if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0)
		DIE_LOG_ERROR("nl_connect: %s", nl_geterror(err));

	if ((err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0)
		DIE_LOG_ERROR("rtnl_link_alloc_cache: %s", nl_geterror(err));

	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL)
		DIE_LOG_ERROR("rtnl_link_get_by_name: no such interface %s",
			      ifname);

	link_change = rtnl_link_alloc();
	if (link_change == NULL) DIE_PERROR("rtnl_link_alloc");

	rtnl_link_set_ns_pid(link_change, target_pid);
	if ((err = rtnl_link_change(sock, link, link_change, 0)) < 0)
		DIE_LOG_ERROR("rtnl_link_change: %s", nl_geterror(err));

	rtnl_link_put(link_change);
	rtnl_link_put(link);
	nl_cache_free(link_cache);
	nl_socket_free(sock);
	return 0;
}

int
net__set_link_updown(const char *ifname, int up)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link;
	int err;

	sock = nl_socket_alloc();
	if (sock == NULL) DIE_PERROR("nl_socket_alloc");

	if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0)
		DIE_LOG_ERROR("nl_connect: %s", nl_geterror(err));

	if ((err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0)
		DIE_LOG_ERROR("rtnl_link_alloc_cache: %s", nl_geterror(err));

	link = rtnl_link_get_by_name(link_cache, ifname);
	if (link == NULL) DIE("sephix: no such interface '%s'\n", ifname);

	if (set_link_updown(sock, link, up) < 0) exit(EXIT_FAILURE);

	rtnl_link_put(link);
	nl_cache_free(link_cache);
	nl_socket_free(sock);
	return 0;
}

int
net__init(struct sandbox_t *sandbox)
{
	return 0;
}
