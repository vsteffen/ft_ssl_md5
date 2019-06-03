/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void	print_inputs(t_ssl *ssl)
{
	t_input			*tmp;
	size_t			i;

	tmp = ssl->inputs;
	i = 0;
	ft_putchar('\n');
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

void	print_bloc(uint8_t *bloc, size_t size)
{
	size_t		i;

	ft_printf("\nDebug: bloc [%p]", (void *)bloc);
	i = 0;
	while (i < size)
	{
		if (i % 16 == 0)
			ft_printf("\n%.8zx ", i);
		if (i % 8 == 0)
			ft_putchar(' ');
		ft_printf(" %.2x", bloc[i]);
		i++;
	}
	ft_printf("\n\n", (void *)bloc);
}
