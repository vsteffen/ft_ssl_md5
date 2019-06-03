/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

char		*md5_to_str(uint8_t *digest)
{
	char		ret[33];
	uint8_t		i;

	i = 0;
	while (i < 16)
	{
		dtoa_hex_ptr(ret + i * 2, digest[i], 2, 0);
		i++;
	}
	ret[32] = '\0';
	return (ft_strdup(ret));
}

void		md5_print(t_ssl *ssl, t_ssl_in *input, char *digest_str)
{
	if (ssl->error)
		print_error_and_reset(ssl);
	else if (input->is_stdin)
	{
		if (ssl->flags_all[SSL_FLAG_P].enable)
			write(1, input->data, input->len);
		ft_printf("%s\n", digest_str);
	}
	else if (ssl->flags_all[SSL_FLAG_Q].enable)
		ft_printf("%s\n", digest_str);
	else if (ssl->flags_all[SSL_FLAG_R].enable)
	{
		if (input->filename)
			ft_printf("%s %s\n", digest_str, input->filename);
		else
			ft_printf("%s \"%s\"\n", digest_str, (char *)input->data);
	}
	else
	{
		if (input->filename)
			ft_printf("MD5 (%s) = %s\n", input->filename, digest_str);
		else
			ft_printf("MD5 (\"%s\") = %s\n", (char *)input->data, digest_str);
	}
}

void		init_md5_struct_and_others(t_md5 *md5, t_ssl *ssl,
	t_ssl_in **cur_input, int8_t *ret)
{
	uint32_t *fln;

	fln = md5->t;
	ft_memcpy(fln, (uint32_t[]){0x0, 0xd76aa478, 0xe8c7b756, 0x242070db,
		0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
		0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
		0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
		0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
		0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
		0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
		0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
		0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7,
		0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f,
		0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
		0xeb86d391}, 65 * sizeof(uint32_t));
	ssl->error_no_usage = 1;
	ssl->res = (char **)malloc(sizeof(char*) * (ssl->inputs_nb + 1));
	md5->ssl = ssl;
	*ret = 1;
	*cur_input = ssl->inputs;
}

void		md5_handle_in_type(t_md5 *md5, t_ssl_in *cur_input, int8_t *ret_tmp)
{
	ft_memcpy(md5->digest, (uint8_t[]){
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	}, 16);
	*ret_tmp = cur_input->filename ? handle_md5_file(md5, cur_input)
		: handle_md5_raw(md5, cur_input);
}

int8_t		handle_md5(t_ssl *ssl)
{
	t_ssl_in	*cur_input;
	t_md5		md5;
	int8_t		ret;
	int8_t		ret_tmp;
	uint8_t		i_res;

	init_md5_struct_and_others(&md5, ssl, &cur_input, &ret);
	i_res = 0;
	while (cur_input)
	{
		md5_handle_in_type(&md5, cur_input, &ret_tmp);
		if (!ret_tmp)
		{
			ret = 0;
			ssl->res[i_res] = ft_strdup("");
		}
		else
			ssl->res[i_res] = md5_to_str(md5.digest);
		if (ssl->verbose)
			md5_print(ssl, cur_input, ssl->res[i_res]);
		cur_input = cur_input->next;
		i_res++;
	}
	ssl->res[i_res] = NULL;
	return (ret);
}
