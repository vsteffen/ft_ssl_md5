/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   shell.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int8_t			shell_compare(const char *cmd, const char *input)
{
	size_t		i;

	i = 0;
	while(cmd[i])
	{
		if (!input[i] || !(cmd[i] == ft_toupper(input[i])))
			return (0);
		i++;
	}
	return (1);
}

void			shell_reinit_struct_ssl(t_ssl *ssl)
{
	free_array_str(ssl->res);
	ssl->res = NULL;
	ssl->crypt = NULL;
	free_inputs(ssl);
	ssl->inputs = NULL;
	ssl->inputs = 0;
	ssl->cur_arg = 0;
}

int8_t			handle_shell(t_ssl *ssl)
{
	int		ret;
	char	*line;

	ft_printf(SSL_SHELL_PROMPT);
	ssl->error_no_usage = 1;
	while ((ret = get_next_line(0, &line)) >= 0)
	{
		if (!ret && ft_strlen(line) == 0)
		{
			ft_printf("\n");
			free(line);
			return (1);
		}
		if (shell_compare("EXIT", line))
		{
			free(line);
			return (1);
		}
		if (shell_compare("HELP", line))
			ft_printf(SSL_USAGE_SHELL);
		else
		{
			ssl->args = ft_strsplitwhite(line);
			if (*ssl->args)
			{
				if (!parse_args(ssl, ssl->args))
				{
					ssl->error = SSL_INVALID_SHELL;
					ssl->error_more_1 = line;
					print_error_and_reset(ssl);
				}
				if (ssl->crypt)
					ssl->crypt->func(ssl);
				shell_reinit_struct_ssl(ssl);
			}
			free_array_str(ssl->args);
		}
		ft_printf(SSL_SHELL_PROMPT);
		free(line);
	}
	return (1);
}
