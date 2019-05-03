#include "ft_ssl_md5.h"

void		print_md5_res(t_ssl *ssl)
{
	(void)ssl;
	ft_printf("Print md5 res here\n");
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
	char	tmp;
	size_t	data_read;

	data_read = input->len;
	while (data_read + 64 > input->len)
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
	t_input		*input;
	char		iv[16];
	int8_t		ret;
	int8_t		ret_tmp;

	ft_memcpy(iv, (char *){0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}, 16);
	tmp = ssl->input;
	ret = 1;
	while (tmp)
	{
		if (tmp->filename)
			ret_tmp = handle_md5_file(ssl, tmp, iv);
		else
			ret_tmp = handle_md5_raw(ssl, tmp, iv);
		if (!ret_tmp)
			ret = 0;
		if (ssl->verbose)
			print_md5_res;
		tmp = tmp->next;
	}
	return (ret);
}