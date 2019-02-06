#include "traceroute.h"

/* sysctl -w net.ipv4.ping_group_range="0 0" */

int		handle_timer(struct timeval *now, struct timeval *past)
{
	int time = now->tv_sec - past->tv_sec;
	if (time == 0)
		return time;
	time *= 1000;
	time += (now->tv_usec - past->tv_usec) / 1000;
	return time;
}

void	send_request(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == -1) {
			perror("gettimeofday "); exit(EXIT_FAILURE);
	}
		socklen_t addrlen = sizeof(struct sockaddr);
		if (sendto(env.soc, &env.to_send, sizeof(env.to_send), 0, (const struct sockaddr*)env.addrinfo->ai_addr, addrlen) != -1) {
		} else {
			perror("connect"); exit(EXIT_FAILURE);
		}
}

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	is_root();
	get_options(argc, argv);
	init_env_socket(env.domain);
	ft_bzero(&env.to_send, sizeof(env.to_send));
	init_iphdr(&env.to_send.ip, &((struct sockaddr_in*)env.addrinfo->ai_addr)->sin_addr);
	init_icmphdr(&env.to_send.icmp);
	init_receive_buffer();
	env.send_packet = 0;
	if (gettimeofday(&env.time, NULL) == -1) {
		perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	printf("traceroute to %s (%s), 30 hops max, 60 byte packets\n", env.domain,\
		inet_ntoa(((struct sockaddr_in*)(env.addrinfo->ai_addr))->sin_addr));
	t_bool response_recv = TRUE;
	struct timeval send_timestamp;
	struct timeval timeout;
	uint32_t	count = 0;
	uint32_t	seq;
	uint32_t	seq_count;
	for (;;) {
		if (response_recv == TRUE) {
			count++;
			env.to_send.ip.ip_ttl++;
			for (seq = 1; seq < 4; seq++) {
				gettimeofday(&send_timestamp, NULL);
				env.to_send.time = send_timestamp.tv_usec;
				env.to_send.icmp.un.echo.sequence = seq;
				env.to_send.icmp.checksum = 0;
				env.to_send.icmp.checksum = compute_checksum(&env.to_send.icmp, sizeof(struct buffer) - sizeof(struct ip));
				send_request();
				response_recv = FALSE;
				seq_count = 0;
			}
		}
		if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), MSG_DONTWAIT, env.addrinfo->ai_addr, &env.addrinfo->ai_addrlen) != -1) {
			struct hostent *p;
			if ((p = gethostbyaddr(&env.to_recv.ip.ip_src.s_addr, 8, AF_INET))) {
					printf("%d  %s (%s)  0ms 0ms 0ms -- ", count, p->h_name, inet_ntoa(env.to_recv.ip.ip_src));
			} else {
					printf("%d  %s (%s)  0ms 0ms 0ms -- ", count, inet_ntoa(env.to_recv.ip.ip_src), inet_ntoa(env.to_recv.ip.ip_src));
			}
			if (env.to_recv.icmp.type == ICMP_TIME_EXCEEDED) {
	//				ft_putendl("ICMP_TIME_EXCEEDED");
			} else if (env.to_recv.icmp.type == ICMP_ECHOREPLY) {
	//				ft_putendl("ICMP_ECHOREPLY");
					break ;
			} else {
					ft_putendl("UNKNOWN");
			}
			seq_count++;
			if (seq_count == 3) {
				printf("\n");
				response_recv = TRUE;
			}
		}
		gettimeofday(&timeout, NULL);
		if (response_recv == FALSE && timeout.tv_sec - send_timestamp.tv_sec >= 3) {
			printf("%d  * * *\n", count);
			response_recv = TRUE;
		}
	}
	return (EXIT_SUCCESS);
}
