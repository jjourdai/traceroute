/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/12 12:28:59 by jjourdai          #+#    #+#             */
/*   Updated: 2018/09/19 14:01:29 by jjourdai         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <traceroute.h>

void	longname_opt(char *str)
{
	(void)str;
	fprintf(stderr, "ping: function not inplemented\n");
	exit(EXIT_FAILURE);
}

static t_parameters *store_parameters(char *str, enum options flag)
{
	static t_parameters new_param;

	new_param.str = str;
	new_param.code = flag;
	return (&new_param);
}

static struct params_getter options[] = {
	{"help", 'h', HELP, NULL},
};

t_list		*get_params(char **argv, int argc, uint8_t *flag)
{
	int 	i, j, flag_has_found;
	uint8_t	index;
	char	c;
	t_list	*parameters;

	i = 0;
	parameters = NULL;
	while (++i < argc)
	{
		if (ft_strncmp(argv[i], "--", 2) == 0) {
				longname_opt(argv[1]);
		}
		else if (argv[i][0] == '-') {
			j = 0;
			while ((c = argv[i][++j]))
			{
				index = -1;
				flag_has_found = 0;
				while (++index < COUNT_OF(options))
				{
					if (options[index].short_name == c) {
						flag_has_found = 1;
						*flag |= options[index].code;
						if (options[index].f != NULL) {
							if (argv[i][j + 1] != '\0')
									list_push_back(&parameters,\
									options[index].f(&argv[i][j + 1],\
									options[index].code), sizeof(t_parameters));
							else if (argv[i + 1] != NULL)
									list_push_back(&parameters,\
									options[index].f(argv[++i],\
									options[index].code), sizeof(t_parameters));
							else {
									fprintf(stderr, "ping: option requires an argument -- '%c'\n", c);
									exit(EXIT_FAILURE);
							}
						}
						break ;
					}
				}
				if (flag_has_found != 1) {
					fprintf(stderr, "ping: invalid option -- '%c'\n", c);
					exit(EXIT_FAILURE);
				} else
					break ;
			}
		}
		else
				list_push_back(&parameters, store_parameters(argv[i], DOMAIN), sizeof(t_parameters));
	}
	return (parameters);
}

void	get_options(int argc, char **argv)
{
	char *ip_addr;
	t_list	*parameters;

	ft_bzero(&env, sizeof(env));
	parameters = get_params(argv, argc, &env.flag.value);
	if (env.flag.value & HELP || (ip_addr = get_targeted_domain(parameters)) == NULL) {
		fprintf(stderr, USAGE); exit(EXIT_FAILURE);
	}
	env.pid = getpid();
	env.domain = ip_addr;
	list_remove(&parameters, remove_content);
}
