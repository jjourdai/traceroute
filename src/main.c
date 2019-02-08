#include "traceroute.h"
#include "colors.h"

/* sysctl -w net.ipv4.ping_group_range="0 0" */

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

void	send_request(void)
{
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

void	store_result(const struct buffer *ptr, struct data *save, struct timeval *stamp)
{
	struct timeval		time;
	struct hostent		*p;
	uint16_t		seq = ptr->icmp.un.echo.sequence - 1; 

	gettimeofday(&time, NULL);
	save[seq].value = (double)handle_timer(&time, &stamp[seq]) / 1000;
	save[seq].s_addr = env.to_recv.ip.ip_src.s_addr;
	save[seq].name = (p = gethostbyaddr(&env.to_recv.ip.ip_src.s_addr, 8, AF_INET)) ? p->h_name : inet_ntoa(env.to_recv.ip.ip_src); 
	save[seq].ip = inet_ntoa(env.to_recv.ip.ip_src);
}

void	print_result(const struct data *save, uint32_t count)
{
	if (save[0].s_addr == save[1].s_addr && save[0].s_addr == save[2].s_addr) {
		printf("%d  %s (%s)  %.3f ms %.3f ms  %.3f ms", count, save[0].name, save[0].ip, save[0].value, save[1].value, save[2].value);
	} else if (save[0].s_addr == save[1].s_addr && save[0].s_addr != save[2].s_addr) {
		printf("%d  %s (%s)  %.3f ms %.3f ms  %s (%s) %.3f ms", count, save[0].name, save[0].ip, save[0].value, save[1].value, save[2].name, save[2].ip, save[2].value);
	} else if (save[0].s_addr != save[1].s_addr) {
		printf("%d  %s (%s)  %.3f ms  %s (%s) %.3f ms  %s (%s) %.3f ms", count, save[0].name, save[0].ip, save[0].value, save[1].name, save[1].ip, save[1].value, save[2].name, save[2].ip, save[2].value);
	} else {
		printf("Dwadawdaw");
	}
	printf(RED_TEXT("\n%llu %llu %llu\n"), save[0].s_addr, save[1].s_addr, save[2].s_addr); 
}

void	loop_exec(void)
{
	t_bool response_recv = TRUE;
	struct timeval send_timestamp, timeout;
	uint32_t	count = 0, seq, seq_count;
	struct data 	save[3];
	struct timeval stamp[3];
	for (;;) {
		if (response_recv == TRUE) {
			count++;
			env.to_send.ip.ip_ttl++;
			for (seq = 1; seq < 4; seq++) {
				env.to_send.icmp.un.echo.sequence = seq; env.to_send.icmp.checksum = 0;
				env.to_send.icmp.checksum = compute_checksum(&env.to_send.icmp, sizeof(struct buffer) - sizeof(struct ip));
				if (gettimeofday(&send_timestamp, NULL) == -1) { perror("gettimeofday:"); }
					stamp[seq - 1] = send_timestamp;
				send_request(); response_recv = FALSE; seq_count = 0;
			}
		}
		ft_bzero(&env.to_recv, sizeof(struct buffer));
		if (recvfrom(env.soc, &env.to_recv, sizeof(struct buffer), MSG_DONTWAIT, env.addrinfo->ai_addr, &env.addrinfo->ai_addrlen) != -1) {
			if (env.to_recv.icmp.type == ICMP_TIME_EXCEEDED) {
				store_result(((void*)env.to_recv.data), save, stamp);
	//				ft_putendl("ICMP_TIME_EXCEEDED");
			} else if (env.to_recv.icmp.type == ICMP_ECHOREPLY) {
				store_result((void*)&env.to_recv, save, stamp);
	//				ft_putendl("ICMP_ECHOREPLY");
					break ;
			} else {
				ft_putendl("UNKNOWN");
			}
			seq_count++;
			if (seq_count == 3) {
				print_result(save, count);
				printf("\n"); response_recv = TRUE; ft_bzero(save, sizeof(save));
			}
		}
		gettimeofday(&timeout, NULL);
		if (response_recv == FALSE && timeout.tv_sec - send_timestamp.tv_sec >= 3) {
			printf("%d  * * *\n", count);
			response_recv = TRUE;
		}
	}
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
	loop_exec();
	return (EXIT_SUCCESS);
}
