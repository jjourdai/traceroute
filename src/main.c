#include "traceroute.h"
#include "colors.h"

/* sysctl -w net.ipv4.ping_group_range="0 0" */

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

void	send_request(struct data *packets, uint32_t seq)
{
	socklen_t addrlen = sizeof(struct sockaddr);

	env.to_send.ip.ip_ttl = (seq - 1) / 3 + 1;
	//printf("%d\n", env.to_send.ip.ip_ttl);
	env.to_send.icmp.un.echo.sequence = seq - 1; env.to_send.icmp.checksum = 0;
	env.to_send.icmp.checksum = compute_checksum(&env.to_send.icmp, sizeof(struct buffer) - sizeof(struct ip));
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
	uint16_t			seq = ptr->icmp.un.echo.sequence; 

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

void	print_result(struct data *packets, uint32_t seq)
{
	uint32_t	i = -1;
	uint32_t	t;

	while (++i < seq)
	{
		t = i * 3;
		fill_string(packets, t);
		if (packets[t].value == 0) {
			printf("%2d  * * *\n", i + 1);
		} else {
	//		printf("%llx %llx %llx\n", packets[t].s_addr, packets[t + 1].s_addr, packets[t + 2].s_addr);
	//		printf("%s %s %s\n", packets[t].ip, packets[t + 1].ip, packets[t + 2].ip);
			if (packets[t].s_addr == packets[t + 1].s_addr && packets[t].s_addr == packets[t + 2].s_addr) {
					printf("%2d  %s (%s)  %.3f ms %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].value);
			} else if (packets[t].s_addr == packets[t + 1].s_addr && packets[t].s_addr != packets[t + 2].s_addr) {
					printf("%2d  %s (%s)  %.3f ms %.3f ms  %s (%s) %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].name, packets[t + 2].ip, packets[t + 2].value);
			} else if (packets[t].s_addr != packets[t + 1].s_addr) {
					printf("%2d  %s (%s)  %.3f ms  %s (%s) %.3f ms  %s (%s) %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].name, packets[t + 1].ip, packets[t + 1].value, packets[t + 2].name, packets[t + 2].ip, packets[t + 2].value);
			} else {
					printf("Dwadawdaw");
			}
//			printf("%2d  %s (%s)  %.3f ms %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].value);
			if (((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == packets[t].s_addr)
					break ;
		}
	}
/*
	printf(RED_TEXT("\n%llu %llu %llu\n"), packets[0].s_addr, packets[1].s_addr, packets[2].s_addr); 
*/
}

void	loop_exec(void)
{
	struct data	*packets = NULL;
	uint32_t	seq_total = env.flag.hops * 3;
	uint32_t	seq = 1;
	fd_set		read, write;
	struct timeval	timeout = {
		.tv_sec = 3, .tv_usec = 0,
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
				ft_putendl("TIMEOUT");	break ;
			}
			if (FD_ISSET(env.soc, &write)) {
					send_request(packets, seq++);
			}
			if (FD_ISSET(env.soc, &read)) {
			//	ft_putendl("RECV");
				ft_bzero(&env.to_recv, sizeof(struct buffer));
				if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), 0, 0, NULL) != -1) {
					if (env.to_recv.icmp.type == ICMP_TIME_EXCEEDED) {
						store_result(((void*)env.to_recv.data), packets);
//						printf("%d ICMP_TIME_EXCEEDED %s\n", ((struct buffer*)env.to_recv.data)->icmp.un.echo.sequence, inet_ntoa(env.to_recv.ip.ip_src));
					} else if (env.to_recv.icmp.type == ICMP_ECHOREPLY) {
						store_result((void*)&env.to_recv, packets);
//						printf("%d ICMP_ECHOREPLY %s\n", env.to_recv.icmp.un.echo.sequence, inet_ntoa(env.to_recv.ip.ip_src));
						//return ;
					} else {
						ft_putendl("UNKNOWN");
					}
				}
			}
/*
		gettimeofday(&timeout, NULL);
		if (response_recv == FALSE && timeout.tv_sec - send_timestamp.tv_sec >= 3) {
			printf("%d  * * *\n", count);
			response_recv = TRUE;
		}
*/
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
	init_icmphdr(&env.to_send.icmp);
	init_receive_buffer();
	env.send_packet = 0;
	if (gettimeofday(&env.time, NULL) == -1) {
		perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	printf("traceroute to %s (%s), %u hops max, 60 byte packets\n", env.domain,\
		inet_ntoa(((struct sockaddr_in*)(env.addrinfo.ai_addr))->sin_addr),\
		env.flag.hops);
	loop_exec();
	return (EXIT_SUCCESS);
}
