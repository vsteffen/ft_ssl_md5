/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   fn_flags.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int8_t	fn_arg_s(t_ssl *ssl, void *data)
{
	(void)data;
	if (ssl->args[ssl->cur_arg + 1])
	{
		ssl->cur_arg++;
		add_input(ssl, create_input(ft_strdup(ssl->args[ssl->cur_arg])
			, NULL, ft_strlen(ssl->args[ssl->cur_arg]), 0));
	}
	else
	{
		ssl->error = SSL_INVALID_FLAG;
		ssl->error_more_1 = ssl->args[ssl->cur_arg];
		return (0);
	}
	return (1);
}
