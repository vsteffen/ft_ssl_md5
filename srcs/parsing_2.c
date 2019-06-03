/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_2.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 17:21:41 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 17:21:43 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int8_t	get_ssl_in_stdin(t_ssl *ssl)
{
	char	*stdin_str;
	char	*tmp;
	char	buff[SSL_BUFF + 1];
	size_t	ret_read;
	size_t	len;

	stdin_str = ft_strdup("");
	len = 0;
	while ((ret_read = read(0, buff, SSL_BUFF)) > 0)
	{
		buff[ret_read] = '\0';
		tmp = (char *)malloc(sizeof(char) * (len + ret_read + 1));
		ft_memcpy(tmp, stdin_str, len);
		ft_memcpy(tmp + len, buff, ret_read + 1);
		free(stdin_str);
		stdin_str = tmp;
		len += ret_read;
	}
	if (ret_read == (size_t)-1)
	{
		free(stdin_str);
		return (0);
	}
	add_input_first(ssl, create_input(stdin_str, NULL, len, 1));
	return (1);
}
