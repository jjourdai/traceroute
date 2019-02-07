
#include "traceroute.h"
#include "colors.h"

void	store_result_udp(const struct buffer *ptr, struct data *packets)
{
	struct timeval		time;
	uint16_t			seq = ntohs(ptr->un.udp.dest) - PORT; 

	gettimeofday(&time, NULL);
	packets[seq].value = (double)handle_timer(&time, &packets[seq].send) / 1000;
	packets[seq].s_addr = env.to_recv.ip.ip_src.s_addr;
	ft_memcpy(packets[seq].ip, inet_ntoa(env.to_recv.ip.ip_src), IP_LEN);
}

void	send_request_udp(struct data *packets, uint32_t seq)
{
	
	char *str = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
	static int port = PORT;
	env.to_send.un.udp.dest = ntohs(port);
	ft_memcpy(&env.to_send.data, str, 32);
	env.to_send.un.udp.check = 0;
	
	socklen_t addrlen = sizeof(struct sockaddr);
	env.to_send.ip.ip_ttl = (seq - 1) / 3 + 1;
	gettimeofday(&packets[port - PORT].send, NULL);
	port++;
	if (sendto(env.soc, &env.to_send, sizeof(env.to_send), 0, (const struct sockaddr*)env.addrinfo.ai_addr, addrlen) != -1) {

	} else {
		perror("sendto"); exit(EXIT_FAILURE);
	}
}

void	loop_exec_udp(void)
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
					send_request_udp(packets, seq++);
			}
			if (FD_ISSET(env.soc, &read)) {
				ft_bzero(&env.to_recv, sizeof(struct buffer));
				if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), 0, NULL, NULL) != -1) {
					if (env.to_recv.un.icmp.type == ICMP_TIME_EXCEEDED) {
						store_result_udp(((void*)&env.to_recv + (sizeof(struct ip) + sizeof(struct udphdr))), packets);
					} else if (env.to_recv.un.icmp.type == ICMP_DEST_UNREACH) {
						store_result_udp(((void*)&env.to_recv + (sizeof(struct ip) + sizeof(struct udphdr))), packets);
					}
				}
			}
	}
	print_result(packets, seq_total / 3);
	free(packets);
}
