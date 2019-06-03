/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools_inputs.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

t_ssl_in	*create_input(char *data, char *filename, size_t len,
	int8_t is_stdin)
{
	t_ssl_in	*new;

	new = (t_ssl_in *)malloc(sizeof(t_ssl_in));
	if (!new)
		return (NULL);
	new->data = data;
	new->len = len;
	new->filename = filename;
	new->fd = -1;
	new->is_stdin = is_stdin;
	new->next = NULL;
	return (new);
}

void		add_input(t_ssl *ssl, t_ssl_in *new_input)
{
	t_ssl_in		*tmp;

	ssl->inputs_nb++;
	tmp = ssl->inputs;
	if (!tmp)
	{
		ssl->inputs = new_input;
		return ;
	}
	while (tmp->next)
		tmp = tmp->next;
	tmp->next = new_input;
}

void		add_input_first(t_ssl *ssl, t_ssl_in *new_input)
{
	t_ssl_in		*tmp;

	ssl->inputs_nb++;
	tmp = ssl->inputs;
	ssl->inputs = new_input;
	if (!tmp)
		return ;
	new_input->next = tmp;
}

void		free_inputs(t_ssl *ssl)
{
	t_ssl_in		*cur;
	t_ssl_in		*tmp;

	cur = ssl->inputs;
	while (cur)
	{
		if (cur->data)
			free(cur->data);
		tmp = cur->next;
		free(cur);
		cur = tmp;
	}
}
