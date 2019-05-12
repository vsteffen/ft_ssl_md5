#include "ft_ssl_md5.h"

void		print_error(t_ssl *ssl)
{
	if (ssl->error_more_3)
		ft_printf(ssl->error, ssl->error_more_1, ssl->error_more_2, ssl->error_more_3);
	else if (ssl->error_more_2)
		ft_printf(ssl->error, ssl->error_more_1, ssl->error_more_2);
	else if (ssl->error_more_1)
		ft_printf(ssl->error, ssl->error_more_1);
	else
		ft_printf(ssl->error);
	if (!ssl->error_no_usage)
		ft_printf(SSL_USAGE);
}

char		**ft_ssl(char **args, int8_t verbose)
{
	struct s_ssl	ssl;

	ft_bzero(&ssl, sizeof(t_ssl));
	ft_memcpy(ssl.crypts, (struct s_crypt[]){{"md5", handle_md5, {0, 1, 2, 3}}, {"sha256", handle_sha_2, {0, 1, 2, 3}}}, sizeof(t_crypt) * SSL_CRYPT_NB);
	ft_memcpy(ssl.flags_all, (struct s_flag[]){{"-p", 0, 0, NULL, NULL}, {"-q", 0, 0, NULL, NULL}, {"-r", 0, 0, NULL, NULL}, {"-s", 0, 0, NULL, fn_arg_s }}, sizeof(t_flag) * SSL_FLAG_NB);
	ssl.args = args;
	ssl.verbose = verbose;
	if (*args)
	{
		if (!parse_args(&ssl, ssl.args) && ssl.verbose)
			print_error(&ssl);
		if (ssl.crypt)
			ssl.crypt->func(&ssl);
		free_inputs(&ssl);
	}
	else
	{
		if (!handle_shell(&ssl))
			print_error(&ssl);
	}
	return (ssl.res);
}

int			main(int ac, char **av)
{
	char	**ret;

	(void)ac;
	ret = ft_ssl(++av, 1);
	if (!ret)
		return (1);
	else
		free_array_str(ret);
	return (0);
}
