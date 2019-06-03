/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static void	fill_zero(size_t length, char *ptr)
{
	if (length > 0)
	{
		while (--length > 0)
			ptr[length] = '0';
		ptr[0] = '0';
	}
}

void		dtoa_hex_ptr(char *ptr, uintmax_t nb, size_t prec,
	int8_t flag_upper)
{
	char		*alph;
	size_t		length;

	length = (size_t)count_numeral_base(nb, 16);
	if (length < prec)
		length = prec;
	ptr[length] = '\0';
	if (flag_upper)
		alph = "0123456789ABCDEF";
	else
		alph = "0123456789abcdef";
	while (nb != 0)
	{
		length--;
		ptr[length] = alph[nb % 16];
		nb /= 16;
	}
	fill_zero(length, ptr);
}

void		free_array_str(char **array)
{
	uint8_t		i;

	i = 0;
	if (!array)
		return ;
	while (array[i])
	{
		free(array[i]);
		i++;
	}
	free(array);
}

void		print_error_and_reset(t_ssl *ssl)
{
	print_error(ssl);
	ssl->error = NULL;
	ssl->error_more_1 = NULL;
	ssl->error_more_2 = NULL;
	ssl->error_more_3 = NULL;
}

int			ssl_open_file(t_ssl *ssl, t_ssl_in *input)
{
	int				fd;
	struct stat		st;

	if (stat(input->filename, &st) == -1)
	{
		ssl->error = SSL_INVALID_FILE_ERRNO;
		ssl->error_more_1 = input->filename;
		ssl->error_more_2 = strerror(errno);
		return (-1);
	}
	if (S_ISDIR(st.st_mode))
	{
		ssl->error = SSL_INVALID_FILE_ISDIR;
		ssl->error_more_1 = input->filename;
		return (-1);
	}
	if ((fd = open(input->filename, O_RDWR)) == -1)
	{
		ssl->error = SSL_INVALID_FILE_ERRNO;
		ssl->error_more_1 = input->filename;
		ssl->error_more_2 = strerror(errno);
	}
	return (fd);
}
