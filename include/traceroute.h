/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   traceroute.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/17 18:12:39 by jjourdai          #+#    #+#             */
/*   Updated: 2019/02/01 11:03:40 by jjourdai         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TRACEROUTE_H
# define TRACEROUTE_H

# include "libft.h"
# include <errno.h>
# include <stdlib.h>
# include <stdio.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netinet/in.h>
# include <netinet/ip_icmp.h>
# include <arpa/inet.h>
# include <sys/select.h>
# include <sys/time.h>
# include <netdb.h>

# define DATA_STR "065465406540545640560465046540654"
# define COUNT_OF(ptr) (sizeof(ptr) / sizeof((ptr)[0]))
# define USAGE "Usage: traceroute [-h] destination\n"
# define ERR_HOPS "first hop out of range\n"
# define TOO_MANY_HOPS "max hops cannot be more than 255\n"

# define HOPS_MAX 30
# define TRUE 1
# define FALSE 0

enum	options {
	HELP = (1 << 0),
	MAX = (1 << 1),
	DOMAIN,
};

struct buffer {
	struct ip		ip;
	struct icmphdr	icmp;
	uint8_t			data[48];
}__attribute__((packed));

struct data {
	struct timeval send;
//	struct timeval recv;
	unsigned long	s_addr;
	double		value;
	char		*name;
	char		*ip;
};

struct traceroute {
	int				soc;
	uint8_t			send_packet;
	uint8_t			recv_packet;
	uint8_t			packet_err;
	uint16_t		pid;
	char			*domain;
	struct timeval	time;
	struct addrinfo	*addrinfo;
	struct buffer	to_send;
	struct buffer	to_recv;
	struct msghdr	msg;
	struct {
		uint8_t	value;
		uint16_t hops;
	} flag;
};

typedef struct parameters {
	char *str;
	enum options code;
}			t_parameters;

struct params_getter {
	char			*long_name;
	char			short_name;
	enum options	code;
	struct parameters *(*f)(char *, enum options);	
};

struct traceroute env;

/* params.c */
t_list	*get_params(char **argv, int argc, uint8_t *flag);
char	*get_targeted_domain(t_list *params); 
uint64_t	get_ttl(t_list *params); 
void	get_options(int argc, char **argv);

/* display_recv_packet.c */
void	print_receive_packet(void);

/* init.c */

void		init_iphdr(struct ip *ip, struct in_addr *dest);
void		init_icmphdr(struct icmphdr *icmp);
void		init_env_socket(char *domain);
void		init_receive_buffer(void);

#endif
