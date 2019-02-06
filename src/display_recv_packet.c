#include "traceroute.h"

static char *icmp_error[] = {
		[ICMP_DEST_UNREACH] = "Destination Unreachable",
		[ICMP_SOURCE_QUENCH] = "Source Quench",
		[ICMP_REDIRECT] = "Redirect (change route)",
		[ICMP_TIME_EXCEEDED] = "Time to live exceeded",
		[ICMP_PARAMETERPROB] = "Parameter Problem",
		[ICMP_TIMESTAMP] = "Timestamp Request",
		[ICMP_TIMESTAMPREPLY] = "Timestamp Reply",
		[ICMP_INFO_REQUEST] = "Information Request",
		[ICMP_INFO_REPLY] = "Information Reply",
		[ICMP_ADDRESS] = "Address Mask Request",
		[ICMP_ADDRESSREPLY] = "Address Mask Reply",
};

void	print_receive_packet(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
			perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	struct hostent *p;
	if (env.to_recv.icmp.type == ICMP_ECHOREPLY) {
		env.recv_packet++;
		if ((p = gethostbyaddr(&env.to_recv.ip.ip_src.s_addr, 8, AF_INET)) != NULL) {
			printf("%lu bytes from %s (%s): icmp_seq=%d ttl=%d time=",\
			env.to_recv.ip.ip_len - sizeof(struct ip),\
			p->h_name,\
			inet_ntoa(env.to_recv.ip.ip_src),\
			env.to_recv.icmp.un.echo.sequence,\
			env.to_recv.ip.ip_ttl);
		}
		else {
			printf("%lu bytes from %s: icmp_seq=%d ttl=%d time=",\
			env.to_recv.ip.ip_len - sizeof(struct ip),\
			inet_ntoa(env.to_recv.ip.ip_src),\
			env.to_recv.icmp.un.echo.sequence,\
			env.to_recv.ip.ip_ttl);
		}
	}
	else if (env.to_recv.icmp.type >= 3 && env.to_recv.icmp.type <= 18) {
		printf("From %s icmp_seq=%d %s\n",\
		inet_ntoa(env.to_recv.ip.ip_src),\
		env.to_send.icmp.un.echo.sequence,\
		icmp_error[env.to_recv.icmp.type]);
		env.packet_err++;
	} else {
		printf("Unknown type %d\n",env.to_recv.icmp.type);
	}
	fflush(stdout);
}
