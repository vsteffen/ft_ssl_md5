/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_2_read_input.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 21:40:48 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 21:40:50 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		sha_2_padding_file(uint8_t *bloc, int16_t len_left, t_sha_2 *sha_2)
{
	uint8_t		i;

	i = len_left;
	if (!sha_2->padding_first_bit)
		bloc[i++] = 0x80;
	while (i < sha_2->buff_size)
		bloc[i++] = 0;
	sha_2->padding_first_bit = 1;
}

void		sha_2_padding_raw(uint8_t *bloc, uint8_t *data_left,
	int16_t len_left, t_sha_2 *sha_2)
{
	uint8_t		i;

	i = 0;
	while (i < len_left)
	{
		bloc[i] = data_left[i];
		i++;
	}
	if (!sha_2->padding_first_bit)
		bloc[i++] = 0x80;
	while (i < sha_2->buff_size)
		bloc[i++] = 0;
	sha_2->padding_first_bit = 1;
}

void		handle_sha_2_read_file_and_compute(t_sha_2 *sha_2, t_ssl_in *input)
{
	sha_2->padding_first_bit = 0;
	while ((sha_2->file.ret_read = read(sha_2->file.fd, sha_2->file.buff,
		sha_2->buff_size)) > 0 && sha_2->file.ret_read != (uint8_t)-1)
	{
		if (input->is_stdin && sha_2->ssl->flags_all[SSL_FLAG_P].enable)
			write(1, sha_2->file.buff, sha_2->file.ret_read);
		input->len += sha_2->file.ret_read;
		if (sha_2->file.ret_read < sha_2->buff_size)
		{
			sha_2_padding_file(sha_2->file.buff, sha_2->file.ret_read, sha_2);
			if (sha_2->file.ret_read
				< (sha_2->buff_size - sha_2->padding_length))
				sha_2_padding_length(sha_2->file.buff, input->len, sha_2);
			else
				sha_2->padding_first_bit = 2;
			sha_2_update(sha_2, sha_2->file.buff);
			break ;
		}
		else
			sha_2_update(sha_2, sha_2->file.buff);
	}
}

int8_t		handle_sha_2_file(t_sha_2 *sha_2, t_ssl_in *input)
{
	if ((sha_2->file.fd = ssl_open_file(sha_2->ssl, input)) == -1)
		return (0);
	handle_sha_2_read_file_and_compute(sha_2, input);
	if (sha_2->padding_first_bit == 0 || sha_2->padding_first_bit == 2)
	{
		sha_2_padding_file(sha_2->file.buff, 0, sha_2);
		sha_2_padding_length(sha_2->file.buff, input->len, sha_2);
		sha_2_update(sha_2, sha_2->file.buff);
	}
	if (sha_2->file.ret_read == (uint8_t)-1)
	{
		sha_2->ssl->error_no_usage = 1;
		sha_2->ssl->error = SSL_INVALID_FILE_ERRNO;
		sha_2->ssl->error_more_1 = input->filename;
		sha_2->ssl->error_more_2 = strerror(errno);
		return (0);
	}
	close(sha_2->file.fd);
	return (1);
}

int8_t		handle_sha_2_raw(t_sha_2 *sha_2, t_ssl_in *input)
{
	uint8_t	bloc_padded[sha_2->buff_size];
	size_t	data_read;

	data_read = 0;
	sha_2->padding_first_bit = 0;
	while (data_read + (sha_2->buff_size - sha_2->padding_length)
		<= input->len)
	{
		if ((input->len - data_read) < sha_2->buff_size)
		{
			sha_2_padding_raw(bloc_padded, (uint8_t *)
				(input->data + data_read), input->len - data_read, sha_2);
			sha_2_update(sha_2, bloc_padded);
			data_read = input->len;
			break ;
		}
		sha_2_update(sha_2, (uint8_t *)(input->data + data_read));
		data_read += sha_2->buff_size;
	}
	sha_2_padding_raw(bloc_padded, (uint8_t *)
		(input->data + data_read), input->len - data_read, sha_2);
	sha_2_padding_length(bloc_padded, input->len, sha_2);
	sha_2_update(sha_2, bloc_padded);
	return (1);
}
