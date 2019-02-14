#include "traceroute.h"
#include "colors.h"

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

void	send_request_icmp(struct data *packets, uint32_t seq)
{
	socklen_t addrlen = sizeof(struct sockaddr);
	
	env.to_send.ip.ip_ttl = (seq - 1) / 3 + 1;
	env.to_send.un.icmp.un.echo.sequence = seq - 1; env.to_send.un.icmp.checksum = 0;
	env.to_send.un.icmp.checksum = compute_checksum(&env.to_send.un.icmp, sizeof(struct buffer) - sizeof(struct ip));
	gettimeofday(&packets[seq - 1].send, NULL);
	if (sendto(env.soc, &env.to_send, sizeof(env.to_send), 0, (const struct sockaddr*)env.addrinfo.ai_addr, addrlen) != -1) {

	} else {
		perror("sendto"); exit(EXIT_FAILURE);
	}
}

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

void	store_result(const struct buffer *ptr, struct data *packets)
{
	struct timeval		time;
	uint16_t			seq = ptr->un.icmp.un.echo.sequence; 

	gettimeofday(&time, NULL);
	packets[seq].value = (double)handle_timer(&time, &packets[seq].send) / 1000;
	packets[seq].s_addr = env.to_recv.ip.ip_src.s_addr;
	ft_memcpy(packets[seq].ip, inet_ntoa(env.to_recv.ip.ip_src), IP_LEN);
}

void	fill_string(struct data *packets, uint32_t t)
{
	uint32_t i = 0;
	struct hostent		*p;
	size_t				len = 0;

	for (; i < 3; i++)
	{
		if ((p = gethostbyaddr(&packets[t + i].s_addr, 8, AF_INET))) {
			len = ft_strlen(p->h_name);
		}
		if (p)
			ft_memcpy(packets[t + i].name, p->h_name, (len > NAME_LEN) ? NAME_LEN : len);
		else
			ft_memcpy(packets[t + i].name, packets[t + i].ip, IP_LEN);
	}
}

void	loop_exec_icmp(void)
{
	struct data	*packets = NULL;
	uint32_t	seq_total = env.flag.hops * 3;
	uint32_t	seq = 1;
	fd_set		read, write;
	struct timeval	timeout = {
		.tv_sec = 1, .tv_usec = 0,
	};
	if ((packets = ft_memalloc(sizeof(struct data) * seq_total)) == NULL) {
		fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
	}
	for (;;) {
			FD_ZERO(&read);	FD_ZERO(&write);
			FD_SET(env.soc, &read);
			if (seq <= seq_total)
				FD_SET(env.soc, &write);
			if (select(env.soc + 1, &read, &write, NULL, &timeout) == 0) {
					break ;
			}
			if (FD_ISSET(env.soc, &write)) {
					send_request_icmp(packets, seq++);
			}
			if (FD_ISSET(env.soc, &read)) {
				ft_bzero(&env.to_recv, sizeof(struct buffer));
				if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), 0, NULL, NULL) != -1) {
					if (env.to_recv.un.icmp.type == ICMP_TIME_EXCEEDED) {
						store_result(((void*)&env.to_recv + (sizeof(struct ip) + sizeof(struct icmphdr))), packets);
					} else if (env.to_recv.un.icmp.type == ICMP_ECHOREPLY) {
						store_result((void*)&env.to_recv, packets);
					}
				}
			}
	}
	print_result(packets, seq_total / 3);
	free(packets);
}

int main(int argc, char **argv)
{
	is_root();
	get_options(argc, argv);
	init_env_socket(env.domain);
	ft_bzero(&env.to_send, sizeof(env.to_send));
	init_iphdr(&env.to_send.ip, &((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr);
	if (env.proto == IPPROTO_UDP) {
		init_udphdr(&env.to_send.un.udp);
	} else if (env.proto == IPPROTO_TCP) {
		init_tcphdr(&env.to_send.un.tcp);
	} else {
		init_icmphdr(&env.to_send.un.icmp);
	}
	env.send_packet = 0;
	if (gettimeofday(&env.time, NULL) == -1) {
		perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	printf("traceroute to %s (%s), %u hops max, %lu byte packets\n", env.domain,\
		inet_ntoa(((struct sockaddr_in*)(env.addrinfo.ai_addr))->sin_addr),\
		env.flag.hops, sizeof(struct buffer));
	if (env.proto == IPPROTO_UDP) {
		loop_exec_udp();
	} else if (env.proto == IPPROTO_TCP) {
		loop_exec_tcp();
	} else {
		loop_exec_icmp();
	}
	return (EXIT_SUCCESS);
}

