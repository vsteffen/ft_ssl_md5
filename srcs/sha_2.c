#include "ft_ssl_md5.h"

char		*sha_2_to_str(uint8_t *digest, t_sha_2 *sha_2)
{
	char		ret[sha_2->digest_size + 1];
	uint8_t		i;
	uint8_t		char_in_digest_bloc;

	i = 0;
	char_in_digest_bloc = sha_2->digest_size / 2;
	while (i < char_in_digest_bloc)
	{
		dtoa_hex_ptr(ret + i * 2, digest[i], 2, 0);
		i++;
	}
	ret[sha_2->digest_size] = '\0';
	return (ft_strdup(ret));
}

void		sha_2_print(t_ssl *ssl, t_input *input, char *digest_str)
{
	if (ssl->error)
		print_error_and_reset(ssl);
	else if (input->is_stdin)
	{
		if (ssl->flags_all[SSL_FLAG_P].enable)
			ft_printf("%s", (char *)input->data);
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
			ft_printf("%s (%s) = %s\n", ssl->crypt->name, input->filename, digest_str);
		else
			ft_printf("%s (\"%s\") = %s\n", ssl->crypt->name, (char *)input->data, digest_str);
	}
}

void		sha_2_update(t_sha_2 *sha_2, uint8_t *bloc, uint8_t *digest, uint64_t t[65])
{
	// t_sha_2_words		words;
	print_bloc(bloc, sha_2->buff_size);
	(void)sha_2;
	(void)bloc;
	(void)digest;
	(void)t;
	// words.a = *(uint32_t *)(digest + 0);
	// words.b = *(uint32_t *)(digest + 4);
	// words.c = *(uint32_t *)(digest + 8);
	// words.d = *(uint32_t *)(digest + 12);
	// sha_2_rounds(&words, bloc, t);
	// *(uint32_t *)(digest + 0) = words.a;
	// *(uint32_t *)(digest + 4) = words.b;
	// *(uint32_t *)(digest + 8) = words.c;
	// *(uint32_t *)(digest + 12) = words.d;
}

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

void		sha_2_padding_raw(uint8_t *bloc, uint8_t *data_left, int16_t len_left, t_sha_2 *sha_2)
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

void		sha_2_padding_length(uint8_t *bloc, size_t total_len, t_sha_2 *sha_2)
{
	*(uint64_t *)(bloc + (sha_2->buff_size - 8)) = swap_uint64((uint64_t)total_len << 3);
}

int			sha_2_open_file(t_ssl *ssl, t_input *input)
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

int8_t		handle_sha_2_file(t_sha_2 *sha_2, t_input *input, uint8_t *digest, uint64_t t[65])
{
	int		fd;
	uint8_t	buff[sha_2->buff_size];
	ssize_t	ret_read;

	if ((fd = sha_2_open_file(sha_2->ssl, input)) == -1)
		return (0);
	while ((ret_read = read(fd, buff, sha_2->buff_size)) > 0)
	{
		input->len += ret_read;
		if (ret_read < (sha_2->buff_size - sha_2->padding_length))
		{
			sha_2_padding_file(buff, ret_read, sha_2);
			sha_2_padding_length(buff, input->len, sha_2);
			sha_2_update(sha_2, buff, digest, t);
		}
		else if (ret_read < sha_2->buff_size)
		{
			sha_2_padding_file(buff, ret_read, sha_2);
			sha_2_update(sha_2, buff, digest, t);
			sha_2_padding_file(buff, 0, sha_2);
			sha_2_padding_length(buff, input->len, sha_2);
			sha_2_update(sha_2, buff, digest, t);
		}
		else
			sha_2_update(sha_2, buff, digest, t);
	}
	if (ret_read == (ssize_t)-1)
	{
		sha_2->ssl->error_no_usage = 1;
		sha_2->ssl->error = SSL_INVALID_FILE_ERRNO;
		sha_2->ssl->error_more_1 = input->filename;
		sha_2->ssl->error_more_2 = strerror(errno);
		return (0);
	}
	close(fd);
	return (1);
}

int8_t		handle_sha_2_raw(t_sha_2 *sha_2, t_input *input, uint8_t *digest, uint64_t t[65])
{
	uint8_t	bloc_padded[sha_2->buff_size];
	size_t	data_read;

	data_read = 0;
	while (data_read + (sha_2->buff_size - sha_2->padding_length) <= input->len)
	{
		if ((input->len - data_read) < sha_2->buff_size)
		{
			sha_2_padding_raw(bloc_padded, (uint8_t *)(input->data + data_read), input->len - data_read, sha_2);
			sha_2_update(sha_2, bloc_padded, digest, t);
			data_read = input->len;
			break ;
		}
		sha_2_update(sha_2, (uint8_t *)(input->data + data_read), digest, t);
		data_read += sha_2->buff_size;
	}
	sha_2_padding_raw(bloc_padded, (uint8_t *)(input->data + data_read), input->len - data_read, sha_2);
	sha_2_padding_length(bloc_padded, input->len, sha_2);
	sha_2_update(sha_2, bloc_padded, digest, t);
	return (1);
}

void		sha_2_init_struct(t_sha_2 *sha_2, t_ssl *ssl)
{
	sha_2->ssl = ssl;
	if (ft_strcmp("sha224", ssl->crypt->name) == 0)
	{
		sha_2->type = SSL_TYPE_SHA_224;
		sha_2->buff_size = SSL_BUFF_SHA_32;
		sha_2->digest_size = SSL_DIGEST_SHA_224;
		sha_2->padding_length = 8;
	}
	else if (ft_strcmp("sha256", ssl->crypt->name) == 0)
	{
		sha_2->type = SSL_TYPE_SHA_256;
		sha_2->buff_size = SSL_BUFF_SHA_32;
		sha_2->digest_size = SSL_DIGEST_SHA_256;
		sha_2->padding_length = 8;
	}
	else if (ft_strcmp("sha384", ssl->crypt->name) == 0)
	{
		sha_2->type = SSL_TYPE_SHA_384;
		sha_2->buff_size = SSL_BUFF_SHA_64;
		sha_2->digest_size = SSL_DIGEST_SHA_384;
		sha_2->padding_length = 16;
	}
	else
	{
		sha_2->type = SSL_TYPE_SHA_512;
		sha_2->buff_size = SSL_BUFF_SHA_64;
		sha_2->digest_size = SSL_DIGEST_SHA_512;
		sha_2->padding_length = 16;
	}
	sha_2->padding_first_bit = 0;
}

void		sha_2_init_digest(t_sha_2 *sha_2, uint64_t *digest)
{
	if (sha_2->type == 0)
		ft_memcpy(digest, (unsigned long[]){0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4}, 8);
	else if (sha_2->type == 1)
		ft_memcpy(digest, (unsigned long[]){0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}, 8);
	else if (sha_2->type == 2)
		ft_memcpy(digest, (unsigned long long[]){0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
			0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}, 8);
	else
		ft_memcpy(digest, (unsigned long long[]){0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
			0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}, 8);
}

void		sha_2_init_t(t_sha_2 *sha_2, uint64_t *t)
{
	if (sha_2->type < 2)
	{
		ft_memcpy(t, (unsigned long[]){
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2},
			64 * sizeof(uint32_t));
	}
	else
	{
		ft_memcpy(t, (unsigned long long[]){
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817}, 
			64 * sizeof(uint64_t));
	}
}

int8_t		handle_sha_2(t_ssl *ssl)
{
	t_sha_2		sha_2;
	t_input		*cur_input;
	uint64_t	digest[8];
	uint64_t	t[64];
	int8_t		ret;
	int8_t		ret_tmp;
	uint8_t		i_res;

	sha_2_init_struct(&sha_2, ssl);
	sha_2_init_t(&sha_2, t);
	cur_input = ssl->inputs;
	ssl->error_no_usage = 1;
	ret = 1;
	ssl->res = (char **)malloc(sizeof(char*) * (ssl->inputs_nb + 1));
	i_res = 0;
	while (cur_input)
	{
		sha_2_init_digest(&sha_2, digest);
		if (cur_input->filename)
			ret_tmp = handle_sha_2_file(&sha_2, cur_input, (uint8_t *)digest, t);
		else
			ret_tmp = handle_sha_2_raw(&sha_2, cur_input, (uint8_t *)digest, t);
		if (!ret_tmp)
		{
			ret = 0;
			ssl->res[i_res] = ft_strdup("");
		}
		else
			ssl->res[i_res] = sha_2_to_str((uint8_t *)digest, &sha_2);
		if (ssl->verbose)
			sha_2_print(ssl, cur_input, ssl->res[i_res]);
		cur_input = cur_input->next;
		i_res++;
	}
	ssl->res[i_res] = NULL;
	return (ret);
}
