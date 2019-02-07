
#include "traceroute.h"
#include "colors.h"

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
			if (env.proto == IPPROTO_UDP || env.proto == IPPROTO_TCP) {
				if (packets[t].s_addr == packets[t + 1].s_addr && packets[t].s_addr == packets[t + 2].s_addr)
					printf("%2d  %s (%s)  %.3f ms %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].value);
				else if (packets[t].s_addr == packets[t + 1].s_addr && packets[t].s_addr != packets[t + 2].s_addr)
					printf("%2d  %s (%s)  %.3f ms %.3f ms %s (%s)  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].name, packets[t + 2].ip, packets[t + 2].value);
				else if (packets[t].s_addr != packets[t + 1].s_addr && packets[t].s_addr != packets[t + 2].s_addr && packets[t + 2].s_addr == packets[t + 1].s_addr)
					printf("%2d  %s (%s)  %.3f ms %s (%s)  %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].name, packets[t + 1].ip, packets[t + 1].value, packets[t + 2].value);
				else if (packets[t].s_addr != packets[t + 1].s_addr && packets[t].s_addr != packets[t + 2].s_addr && packets[t + 2].s_addr != packets[t + 1].s_addr)
						printf("%2d  %s (%s)  %.3f ms %s (%s)  %.3f ms %s (%s)  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].name, packets[t + 1].ip, packets[t + 1].value, packets[t + 2].name, packets[t + 2].ip, packets[t + 2].value);
			} else if (env.proto == IPPROTO_ICMP) {
				if (packets[t].s_addr != 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr != 0)
					printf("%2d  %s (%s)  %.3f ms %.3f ms  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value, packets[t + 2].value);
				else if (packets[t].s_addr == 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr != 0)
					printf("%2d  * %s (%s)  %.3f ms  %.3f ms\n", i + 1, packets[t + 1].name, packets[t + 1].ip, packets[t + 1].value, packets[t + 2].value);
				else if (packets[t].s_addr != 0 && packets[t + 1].s_addr == 0 && packets[t + 2].s_addr != 0)
					printf("%2d  %s (%s)  %.3f ms *  %.3f ms\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 2].value);
				else if (packets[t].s_addr != 0 && packets[t + 1].s_addr != 0 && packets[t + 2].s_addr == 0)
					printf("%2d  %s (%s)  %.3f ms  %.3f ms *\n", i + 1, packets[t].name, packets[t].ip, packets[t].value, packets[t + 1].value);
			}
			if (((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == packets[t].s_addr || ((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == 0) {
					break ;
			}
		}
	}
}
