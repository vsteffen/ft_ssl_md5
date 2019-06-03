/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_read_input.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 20:06:59 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 20:07:00 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		md5_padding_file(uint8_t *bloc, int16_t len_left,
	int8_t *padding_first_bit)
{
	uint8_t		i;

	i = len_left;
	if (!*padding_first_bit)
		bloc[i++] = 0x80;
	while (i < 64)
		bloc[i++] = 0;
	*padding_first_bit = 1;
}

void		md5_padding_raw(uint8_t *bloc, uint8_t *data_left, int16_t len_left,
	int8_t *padding_first_bit)
{
	uint8_t		i;

	i = 0;
	while (i < len_left)
	{
		bloc[i] = data_left[i];
		i++;
	}
	if (!*padding_first_bit)
		bloc[i++] = 0x80;
	while (i < 64)
		bloc[i++] = 0;
	*padding_first_bit = 1;
}

void		handle_md5_read_file_and_compute(t_md5 *md5, t_ssl_in *input,
	int8_t *padding_first_bit)
{
	*padding_first_bit = 0;
	while ((md5->file.ret_read = read(md5->file.fd, md5->file.buff,
		SSL_BUFF_MD5)) > 0 && md5->file.ret_read != (uint8_t)-1)
	{
		if (input->is_stdin && md5->ssl->flags_all[SSL_FLAG_P].enable)
			write(1, md5->file.buff, md5->file.ret_read);
		input->len += md5->file.ret_read;
		if (md5->file.ret_read < 64)
		{
			md5_padding_file(md5->file.buff, md5->file.ret_read,
				padding_first_bit);
			if (md5->file.ret_read < 56)
				md5_padding_length(md5->file.buff, input->len);
			else
				*padding_first_bit = 2;
			md5_update(md5->file.buff, md5);
			break ;
		}
		else
			md5_update(md5->file.buff, md5);
	}
}

int8_t		handle_md5_file(t_md5 *md5, t_ssl_in *input)
{
	int8_t	padding_first_bit;

	if ((md5->file.fd = ssl_open_file(md5->ssl, input)) == -1)
		return (0);
	handle_md5_read_file_and_compute(md5, input, &padding_first_bit);
	if (padding_first_bit == 0 || padding_first_bit == 2)
	{
		md5_padding_file(md5->file.buff, 0, &padding_first_bit);
		md5_padding_length(md5->file.buff, input->len);
		md5_update(md5->file.buff, md5);
	}
	if (md5->file.ret_read == (uint8_t)-1)
	{
		md5->ssl->error_no_usage = 1;
		md5->ssl->error = SSL_INVALID_FILE_ERRNO;
		md5->ssl->error_more_1 = input->filename;
		md5->ssl->error_more_2 = strerror(errno);
		return (0);
	}
	close(md5->file.fd);
	return (1);
}

int8_t		handle_md5_raw(t_md5 *md5, t_ssl_in *input)
{
	uint8_t	bloc_padded[64];
	size_t	data_read;
	int8_t	padding_first_bit;

	data_read = 0;
	padding_first_bit = 0;
	while (data_read + 56 <= input->len)
	{
		if ((input->len - data_read) < 64)
		{
			md5_padding_raw(bloc_padded, (uint8_t *)(input->data + data_read),
				input->len - data_read, &padding_first_bit);
			md5_update(bloc_padded, md5);
			data_read = input->len;
			break ;
		}
		md5_update((uint8_t *)(input->data + data_read), md5);
		data_read += 64;
	}
	md5_padding_raw(bloc_padded, (uint8_t *)(input->data + data_read),
		input->len - data_read, &padding_first_bit);
	md5_padding_length(bloc_padded, input->len);
	md5_update(bloc_padded, md5);
	return (1);
}
