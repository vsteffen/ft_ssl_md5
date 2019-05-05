#include "ft_ssl_md5.h"

void		print_md5_res(t_ssl *ssl, t_input *input)
{
	(void)ssl;
	if (input->is_stdin)
	{
		if (ssl->flags_all[FLAG_P].enable)
			ft_printf("%s", (char *)input->data);
		ft_printf("%s\n", ssl->res);
	}
	else if (ssl->flags_all[FLAG_Q].enable)
		ft_printf("%s\n", ssl->res);
	else if (ssl->flags_all[FLAG_R].enable)
	{
		if (input->filename)
			ft_printf("%s %s\n", ssl->res, input->filename);
		else
			ft_printf("%s \"%s\"\n", ssl->res, (char *)input->data);
	}
	else
	{
		if (input->filename)
			ft_printf("MD5(%s) = %s\n", input->filename, ssl->res);
		else
			ft_printf("MD5(\"%s\") = %s\n", (char *)input->data, ssl->res);
	}
}

int8_t		handle_md5_file(t_ssl *ssl, t_input *input, char *iv)
{
	(void)input;
	(void)iv;
	ft_printf("Handle files here\n");
	ssl->res = ft_strdup("ffffffffffffffffffffffffffffffff");
	return (1);
}

void		md5_padding(char *bloc, char *data_left, uint16_t len_left)
{
	(void)bloc;
	(void)data_left;
	(void)len_left;
	// bloc[64] = 1;

	// ft_memcpy(bloc, data_left, len_left);
}

int8_t		handle_md5_raw(t_ssl *ssl, t_input *input, char *iv)
{
	char	dst[33];
	char	bloc_padded[64];
	// char	tmp;
	size_t	data_read;

	(void)ssl;
	data_read = 0;
	while (data_read + 64 < input->len)
	{
		data_read += 64;
		md5(dst, input->data + data_read, iv);
	}
	if (data_read < input->len)
	{
		md5_padding(bloc_padded, input->data + data_read, data_read);
		md5(dst, bloc_padded, iv);
	}
	return (1);
}

void		md5(char *dst, char *data, char *iv)
{
	(void)data;
	(void)iv;
	ft_strcpy(dst, "d41d8cd98f00b204e9800998ecf8427e");
}

int8_t		handle_md5(t_ssl *ssl)
{
	t_input		*cur_input;
	char		iv[16];
	int8_t		ret;
	int8_t		ret_tmp;

	ft_memcpy(iv, (char[]){0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}, 16);
	cur_input = ssl->inputs;
	ret = 1;
	while (cur_input)
	{
		if (cur_input->filename)
			ret_tmp = handle_md5_file(ssl, cur_input, iv);
		else
			ret_tmp = handle_md5_raw(ssl, cur_input, iv);
		if (!ret_tmp)
			ret = 0;
		if (ssl->verbose)
			print_md5_res(ssl, cur_input);
		cur_input = cur_input->next;
	}
	return (ret);
}