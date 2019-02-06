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
