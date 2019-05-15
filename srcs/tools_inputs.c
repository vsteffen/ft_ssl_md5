#include "ft_ssl_md5.h"

t_input		*create_input(char *data, char *filename, size_t len, int8_t is_stdin)
{
	t_input	*new;

	new = (t_input *)malloc(sizeof(t_input));
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

void	add_input(t_ssl *ssl, t_input *new_input)
{
	t_input		*tmp;

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

void	add_input_first(t_ssl *ssl, t_input *new_input)
{
	t_input		*tmp;

	ssl->inputs_nb++;
	tmp = ssl->inputs;
	ssl->inputs = new_input;
	if (!tmp)
		return ;
	new_input->next = tmp;
}

void	free_inputs(t_ssl *ssl)
{
	t_input		*cur;
	t_input		*tmp;

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