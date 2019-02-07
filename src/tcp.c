
#include "traceroute.h"
#include "colors.h"

void	store_result_tcp(const struct buffer *ptr, struct data *packets, int result)
{
	struct timeval		time;
	uint16_t			seq;
	if (result == 1)
		seq = ntohs(ptr->un.tcp.th_ack) - 1; 
	else
		seq = ntohs(ptr->un.tcp.th_seq) - 1; 
	gettimeofday(&time, NULL);
	packets[seq].value = (double)handle_timer(&time, &packets[seq].send) / 1000;
	packets[seq].s_addr = env.to_recv.ip.ip_src.s_addr;
	ft_memcpy(packets[seq].ip, inet_ntoa(env.to_recv.ip.ip_src), IP_LEN);
}

void	send_request_tcp(struct data *packets, uint32_t seq, int FIN)
{
	char *str = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
	static int port = HTTP_PORT;
	
	if (FIN == 0)
		init_tcphdr(&env.to_send.un.tcp);
	else {
		env.to_send.un.tcp.th_flags = TH_RST;
	}
	env.to_send.un.tcp.th_dport = htons(port);
	env.to_send.un.tcp.th_seq = htons(seq);
	ft_memcpy(&env.to_send.data, str, 32);
	socklen_t addrlen = sizeof(struct sockaddr);
	env.to_send.ip.ip_ttl = (seq - 1) / 3 + 1;
	if (FIN == 0)
	gettimeofday(&packets[seq - 1].send, NULL);
	if (sendto(env.soc, &env.to_send, sizeof(env.to_send), 0, (const struct sockaddr*)env.addrinfo.ai_addr, addrlen) != -1) {

	} else {
		perror("sendto"); exit(EXIT_FAILURE);
	}
}


void	loop_exec_tcp(void)
{
	struct data	*packets = NULL;
	uint32_t	seq_total = env.flag.hops * 3;
	uint32_t	seq = 1;
	fd_set		read, write;
	struct timeval	timeout = {
		.tv_sec = 1, .tv_usec = 0,
	};
	int tcp_sock;

	if ((tcp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		perror("socket "); exit(EXIT_FAILURE);
	}
	int opt_value = 1;
	if (setsockopt(tcp_sock, IPPROTO_IP, IP_HDRINCL, &opt_value, sizeof(opt_value)) < 0) {
			perror("setsockopt"); exit(EXIT_FAILURE);
	}
	if ((packets = ft_memalloc(sizeof(struct data) * seq_total)) == NULL) {
		fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
	}
	int test = TRUE;
	for (;;) {
			FD_ZERO(&read);	FD_ZERO(&write);
			FD_SET(env.soc, &read);
			FD_SET(tcp_sock, &read);
			if (seq <= seq_total)
				FD_SET(env.soc, &write);
			if (select(tcp_sock + 1, &read, &write, NULL, &timeout) == 0) {
					break ;
			}
			if (FD_ISSET(env.soc, &write)) {
					if (test == TRUE) {
						send_request_tcp(packets, seq, 0);
						test = FALSE;
					} else {
						send_request_tcp(packets, seq++, 1);
						test = TRUE;
					}
			}
			if (FD_ISSET(env.soc, &read)) {
				ft_bzero(&env.to_recv, sizeof(struct buffer));
				if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), 0, NULL, NULL) != -1) {
					if (env.to_recv.un.icmp.type == ICMP_TIME_EXCEEDED) {
						store_result_tcp(((void*)&env.to_recv + (sizeof(struct ip) + sizeof(struct icmphdr))), packets, 0);
					} else if (env.to_recv.un.icmp.type == ICMP_DEST_UNREACH) {
						store_result_tcp(((void*)&env.to_recv + (sizeof(struct ip) + sizeof(struct icmphdr))), packets, 0);
					}
				}
			}
			if (FD_ISSET(tcp_sock, &read)) {
				ft_bzero(&env.to_recv, sizeof(struct buffer));
				if (recvfrom(tcp_sock, &env.to_recv, sizeof(struct buffer), 0, NULL, NULL) != -1) {
					if (env.to_recv.ip.ip_src.s_addr == ((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr) {
						store_result_tcp(((void*)&env.to_recv), packets, 1);
					}
				}
			}
	}
	print_result(packets, seq_total / 3);
	free(packets);
}
