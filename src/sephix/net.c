#include "sephix/sandbox.h"
#include "sephix/util.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
netlink_send(int fd, struct nlmsghdr *nh)
{
	struct sockaddr_nl addr = {.nl_family = AF_NETLINK};
	struct iovec iov = {nh, nh->nlmsg_len};
	struct msghdr msg = {&addr, sizeof(addr), &iov, 1, NULL, 0, 0};
	return sendmsg(fd, &msg, 0);
}

int
setup_net_interface(char *interface)
{
	int exit_code = 0;
	int fd;
	unsigned int ifindex;

	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg))];
	char reply_buf[1 << 13];

	struct nlmsghdr *nh;
	struct ifinfomsg *ifi;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		PERROR("socket");
		_EXIT(out, -1);
	}

	ifindex = if_nametoindex(interface);
	if (!ifindex) {
		PERROR("if_nametoindex");
		_EXIT(out, -1);
	}

	memset(buf, 0, sizeof(buf));

	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nh->nlmsg_type = RTM_NEWLINK;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nh->nlmsg_seq = 1;

	ifi = NLMSG_DATA(nh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = IFF_UP;

	if (netlink_send(fd, nh) < 0) {
		PERROR("netlink_send");
		_EXIT(out, -1);
	}

	if (recv(fd, reply_buf, sizeof(reply_buf), 0) < 0) {
		PERROR("recv");
		_EXIT(out, -1);
	}

	fprintf(stderr, "[DEBUG] Device %s is up!\n", interface);

out:
	if (fd > 0) close(fd);
	return exit_code;
}

int
net__init(struct sandbox_t *sandbox)
{
	if (sandbox->clone_flags & CLONE_NEWNET) {
		if (setup_net_interface("lo") < 0) {
			return -1;
		}
	}
	return 0;
}
