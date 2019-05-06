#include "ft_ssl_md5.h"

void		print_md5_res(t_ssl *ssl, t_input *input, uint8_t *digest)
{
	(void)ssl;
	if (input->is_stdin)
	{
		if (ssl->flags_all[FLAG_P].enable)
			ft_printf("%s", (char *)input->data);
		ft_printf("%s\n", digest);
	}
	else if (ssl->flags_all[FLAG_Q].enable)
		ft_printf("%s\n", digest);
	else if (ssl->flags_all[FLAG_R].enable)
	{
		if (input->filename)
			ft_printf("%s %s\n", digest, input->filename);
		else
			ft_printf("%s \"%s\"\n", digest, (char *)input->data);
	}
	else
	{
		if (input->filename)
			ft_printf("MD5(%s) = %s\n", input->filename, digest);
		else
			ft_printf("MD5(\"%s\") = %s\n", (char *)input->data, digest);
	}
}

void		md5_update(uint8_t *bloc, uint8_t *digest)
{
	(void)bloc;
	(void)digest;
	// ft_strcpy(dst, "d41d8cd98f00b204e9800998ecf8427e");
}

int8_t		handle_md5_file(t_ssl *ssl, t_input *input, uint8_t *digest)
{
	(void)input;
	(void)digest;
	ft_printf("Handle files here\n");
	ssl->res = ft_strdup("ffffffffffffffffffffffffffffffff");
	return (1);
}

void		md5_padding(uint8_t *bloc, uint8_t *data_left, uint16_t len_left, int8_t *padding_first_bit)
{
	(void)bloc;
	(void)data_left;
	(void)len_left;
	*padding_first_bit = 1;
}

void		md5_padding_lenght(uint8_t *bloc, size_t total_len)
{
	uint64_t	*len_pos;

	len_pos = (uint64_t *)(bloc + 56);
	*len_pos = (uint64_t)total_len;
}

int8_t		handle_md5_raw(t_ssl *ssl, t_input *input, uint8_t *digest)
{
	uint8_t	bloc_padded[64];
	size_t	data_read;
	int8_t	padding_first_bit;

	(void)ssl;
	data_read = 0;
	padding_first_bit = 0;
	while (data_read + 8 <= input->len)
	{
		if ((input->len - data_read) > 64)
		{
			md5_padding(bloc_padded, (uint8_t *)(input->data + data_read), input->len - data_read, &padding_first_bit);
			md5_update(bloc_padded, digest);
		}
		else
			md5_update((uint8_t *)(input->data + data_read), digest);
		data_read += 64;
	}
	md5_padding(bloc_padded, (uint8_t *)(input->data + data_read), input->len - data_read, &padding_first_bit);
	md5_padding_lenght(bloc_padded, input->len);
	md5_update(bloc_padded, digest);
	return (1);
}

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

int8_t		handle_md5(t_ssl *ssl)
{
	t_input		*cur_input;
	uint8_t		digest[16];
	int8_t		ret;
	int8_t		ret_tmp;

	ft_memcpy(digest, (uint8_t[]){0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}, 16);
	ft_printf("Digest at beginning: [%s]\n", md5_to_str(digest));
	cur_input = ssl->inputs;
	ret = 1;
	while (cur_input)
	{
		if (cur_input->filename)
			ret_tmp = handle_md5_file(ssl, cur_input, digest);
		else
			ret_tmp = handle_md5_raw(ssl, cur_input, digest);
		if (!ret_tmp)
			ret = 0;
		md5_to_str(digest);
		if (ssl->verbose)
			print_md5_res(ssl, cur_input, digest);
		cur_input = cur_input->next;
	}
	return (ret);
}