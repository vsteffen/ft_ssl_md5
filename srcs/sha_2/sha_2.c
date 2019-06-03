/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_2.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

char		*sha_2_to_str(uint8_t *digest, t_sha_2 *sha_2)
{
	char		ret[sha_2->digest_size + 1];
	uint8_t		i;
	uint8_t		char_in_digest_bloc;

	i = 0;
	if (sha_2->type < 2)
		reverse_endian_array_32((uint32_t *)digest, 8);
	else
		reverse_endian_array_64((uint64_t *)digest, 8);
	char_in_digest_bloc = sha_2->digest_size / 2;
	while (i < char_in_digest_bloc)
	{
		dtoa_hex_ptr(ret + i * 2, digest[i], 2, 0);
		i++;
	}
	ret[sha_2->digest_size] = '\0';
	return (ft_strdup(ret));
}

void		sha_2_print(t_ssl *ssl, t_ssl_in *input, char *digest_str)
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
		input->filename
		? ft_printf("%s (%s) = %s\n", ssl->crypt->name, input->filename,
			digest_str)
		: ft_printf("%s (\"%s\") = %s\n", ssl->crypt->name,
			(char *)input->data, digest_str);
	}
}

void		sha_2_handle_in_type(t_sha_2 *sha_2, t_ssl_in *cur_input,
	int8_t *ret_tmp)
{
	sha_2_init_digest(sha_2, sha_2->digest);
	*ret_tmp = cur_input->filename ? handle_sha_2_file(sha_2, cur_input)
		: handle_sha_2_raw(sha_2, cur_input);
}

int8_t		handle_sha_2(t_ssl *ssl)
{
	t_sha_2		sha_2;
	t_ssl_in	*cur_input;
	int8_t		ret;
	int8_t		ret_tmp;

	sha_2_init_struct(&sha_2, ssl, &cur_input, &ret);
	sha_2.i_res = 0;
	while (cur_input)
	{
		sha_2_handle_in_type(&sha_2, cur_input, &ret_tmp);
		if (!ret_tmp)
		{
			ret = 0;
			ssl->res[sha_2.i_res] = ft_strdup("");
		}
		else
			ssl->res[sha_2.i_res] = sha_2_to_str((uint8_t *)(sha_2.digest),
				&sha_2);
		if (ssl->verbose)
			sha_2_print(ssl, cur_input, ssl->res[sha_2.i_res]);
		cur_input = cur_input->next;
		sha_2.i_res++;
	}
	ssl->res[sha_2.i_res] = NULL;
	return (ret);
}
