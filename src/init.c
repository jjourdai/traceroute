
#include "traceroute.h"

struct addrinfo *result_dns(char *domain)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(domain, NULL, &hints, &result) != 0) {
		fprintf(stderr, "ping: unknown host %s\n", domain); exit(EXIT_FAILURE);
	} else {
		return (result);
	}
}

void 	init_iphdr(struct ip *ip, struct in_addr *dest)
{
	ft_bzero(ip, sizeof(*ip));
	ip->ip_v = 4;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(struct buffer));
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 0;
	ip->ip_p = env.proto;
	ip->ip_sum = 0;
	inet_pton(AF_INET, "0.0.0.0", &ip->ip_src);
	ip->ip_dst = *dest;
}

void	init_icmphdr(struct icmphdr *icmp)
{
	ft_bzero(icmp, sizeof(*icmp));
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = env.pid;
	icmp->un.echo.sequence = 1;
	icmp->checksum = 0;
}

void	init_udphdr(struct udphdr *udp)
{
	ft_bzero(udp, sizeof(*udp));
	
	udp->source = htons(64356);
	udp->dest = htons(64356);
	udp->len = htons(sizeof(struct buffer) - sizeof(struct ip));
	udp->check = 0;
}

void	init_env_socket(char *domain)
{
	ft_memcpy(&env.addrinfo, result_dns(domain), sizeof(struct addrinfo));
	if (((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == INADDR_BROADCAST) {
		fprintf(stderr, "Do you want to ping broadcast? but No\n"); exit(EXIT_FAILURE);
	}
	if ((env.soc = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		perror("socket "); exit(EXIT_FAILURE);
	} else {
		int opt_value = 1;
		if (setsockopt(env.soc, IPPROTO_IP, IP_HDRINCL, &opt_value, sizeof(opt_value)) < 0) {
			perror("setsockopt"); exit(EXIT_FAILURE);
		}
	}

//	bind(env.soc, 
}
