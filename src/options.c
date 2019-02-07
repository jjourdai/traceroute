#include "traceroute.h"

char *get_targeted_domain(t_list *params)
{
	t_list *tmp;

	tmp = params;
	while (tmp)
	{
		if (((t_parameters*)(tmp->content))->code == DOMAIN)
			return ((t_parameters*)(tmp->content))->str;
		tmp = tmp->next;
	}
	return (NULL);
}

uint64_t	get_ttl(t_list *params)
{
	t_list *tmp;

	tmp = params;
	while (tmp)
	{
		if (((t_parameters*)(tmp->content))->code == MAX)
			return ft_atoi_u(((t_parameters*)(tmp->content))->str);
		tmp = tmp->next;
	}
	return (0);
}
