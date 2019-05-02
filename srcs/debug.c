#include "ft_ssl_md5.h"

void	print_inputs(t_ssl *ssl)
{
	t_input			*tmp;
	size_t			i;

	tmp = ssl->inputs;
	i = 0;
	while (tmp)
	{
		ft_printf("ARG [%zu]\n", i);
		ft_printf("data		-> [%s]\n", (char *)tmp->data);
		ft_printf("filename	-> [%s]\n", tmp->filename);
		ft_printf("fd		-> [%d]\n", tmp->fd);
		ft_putchar('\n');
		tmp = tmp->next;
		i++;
	}
}