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

void	print_result(struct data *packets, uint32_t seq)
{
	uint32_t	i = -1;
	uint32_t	t;

	while (++i < seq)
	{
		t = i * 3;
		fill_string(packets, t);
		if (packets[t].value == 0 && packets[t + 1].s_addr == 0 && packets[t + 2].s_addr == 0) {
			printf("%2d  * * *\n", i + 1);
		} else {
			if (packets[t].s_addr != 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr != 0)
				printf("%2d  %s (%s)  %.3f ms %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].value);
			else if (packets[t].s_addr == 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr != 0)
				printf("%2d  * %s (%s)  %.3f ms  %.3f ms\n", i + 1, packets[t + 1].name, packets[t + 1].ip, packets[t + 1].value, packets[t + 2].value);
			else if (packets[t].s_addr != 0 && packets[t + 1].s_addr == 0 && packets[t + 2].s_addr != 0)
				printf("%2d  %s (%s)  %.3f ms *  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 2].value);
			else if (packets[t].s_addr != 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr == 0)
				printf("%2d  %s (%s)  %.3f ms  %.3f ms *\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value);
			if (((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == packets[t].s_addr || ((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == 0) {
					break ;
			}
		}
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
						store_result(((void*)&env.to_recv.data), packets);
					} else if (env.to_recv.un.icmp.type == ICMP_ECHOREPLY) {
						store_result((void*)&env.to_recv, packets);
					}
				}
			}
	}
	print_result(packets, seq_total / 3);
	free(packets);
}

struct psdhdr {
    unsigned long	 src_ip;
    unsigned long 	dest_ip;
    char 			mbz;
    char 			proto; // Type de protocole (6->TCP et 17->le mode non connecte)
    unsigned short 	length; // htons( Entete TCP ou non connecte + Data )
	struct udphdr 	udp;
	uint8_t			data[32];
//};
}__attribute__((packed));

void	send_request_udp(struct data *packets, uint32_t seq)
{

/*
 	pseudo.ip_source=ip_source_tampon;
     pseudo.ip_destination=ip_destination_tampon;
     pseudo.mbz=0;
     pseudo.type=17;
     pseudo.length=htons((unsigned short)(sizeof(struct entete)+(unsigned short)strlen(data_tampon)));
     memcpy(tampon,&pseudo,sizeof(pseudo));
     memcpy(tampon+sizeof(pseudo),&Tampon,sizeof(struct entete));
     memcpy(tampon+sizeof(pseudo)+sizeof(struct entete),data_tampon,strlen(data_tampon));
     checksum=calcul_du_checksum(liberation,(unsigned short*)tampon,sizeof(pseudo)+sizeof(struct entete)+strlen(data_tampon));
*/
	struct psdhdr psd;
	
	char *str = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";

	env.to_send.ip.ip_src.s_addr = inet_addr("10.16.239.165");

	ft_bzero(&psd, sizeof(struct psdhdr));
	ft_memcpy(&env.to_send.data, str, 32);
	ft_memcpy(&psd.data, &env.to_send.data, 32);
	psd.src_ip = env.to_send.ip.ip_src.s_addr;
	psd.dest_ip = env.to_send.ip.ip_dst.s_addr;
	psd.mbz = 0;
	psd.proto = IPPROTO_UDP;
	psd.length = htons(sizeof(struct udphdr) + 32);
	env.to_send.un.udp.check = 0;
	ft_memcpy(&psd.udp, &env.to_send.un.udp, sizeof(struct udphdr));
	
	socklen_t addrlen = sizeof(struct sockaddr);

	env.to_send.ip.ip_ttl = (seq - 1) / 3 + 1;
//	env.to_send.un.udp.check = htons(0x9eb8);
	env.to_send.un.udp.check = compute_checksum(&psd, sizeof(struct psdhdr));
	//env.to_send.un.udp.check = compute_checksum(&psd, sizeof(struct psdhdr));

//	printf("%llx\n", psd.dest_ip);
//	printf("%llx\n", psd.src_ip);
//	printf("checksum %llx\n", env.to_send.un.udp.check);
	gettimeofday(&packets[seq - 1].send, NULL);
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
	fd_set		read, writefd;
	struct timeval	timeout = {
		.tv_sec = 1, .tv_usec = 0,
	};
	if ((packets = ft_memalloc(sizeof(struct data) * seq_total)) == NULL) {
		fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
	}

	int test = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	printf("%d\n", test);
	char *str = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
	socklen_t addrlen = sizeof(struct sockaddr);
	ft_memcpy(&env.to_send.data, str, 32);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = 0,
	};
	struct sockaddr_in addr2 = {
		.sin_family = AF_INET,
		.sin_port = 22,
		.sin_addr = inet_addr("216.58.213.174"),
	};
	if (bind(test, (const struct sockaddr*)&addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
	}
	int opt_value = 1;
	if (setsockopt(test, SOL_IP, IP_RECVERR, &opt_value, sizeof(opt_value)) == -1) {
		perror("setsockopt");
	}
	opt_value = 1;
	if (setsockopt(test, SOL_IP, IP_RECVTTL, &opt_value, sizeof(opt_value)) == -1) {
		perror("setsockopt");
	}
	opt_value = 6;
	if (setsockopt(test, SOL_IP, IP_TTL, &opt_value, sizeof(opt_value)) == -1) {
		perror("setsockopt");
	}
	if (sendto(test, &env.to_send.data, sizeof(env.to_send.data), 0, (const struct sockaddr*)&addr2, addrlen) == -1) {
		perror("ERROR ");
	}
	
	ft_bzero(&env.to_recv, sizeof(env.to_recv));
	if (recvfrom(test, &env.to_recv, sizeof(struct buffer), 0, NULL, NULL) != -1) {
		ft_putendl("dwalhdawkdjaw");
	} else {
		perror("recfrom ");
		if (env.to_recv.un.icmp.type == ICMP_TIME_EXCEEDED) {
			ft_putendl("ICMP_TIME_EXCEEDED");
		}
	}
	exit(0);
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
	} else if (env.proto == IPPROTO_ICMP) {
		init_icmphdr(&env.to_send.un.icmp);
	}
	env.send_packet = 0;
	if (gettimeofday(&env.time, NULL) == -1) {
		perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	printf("traceroute to %s (%s), %u hops max, 60 byte packets\n", env.domain,\
		inet_ntoa(((struct sockaddr_in*)(env.addrinfo.ai_addr))->sin_addr),\
		env.flag.hops);
	if (env.proto == IPPROTO_UDP) {
		loop_exec_udp();
	} else if (env.proto == IPPROTO_ICMP) {
		loop_exec_icmp();
	}
	return (EXIT_SUCCESS);
}
