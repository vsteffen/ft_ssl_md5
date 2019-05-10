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

char		*ft_ssl(char **args, int8_t verbose)
{
	struct s_ssl	ssl;

	ft_bzero(&ssl, sizeof(t_ssl));
	ft_memcpy(ssl.crypts, (struct s_crypt[]){{"md5", handle_md5, {0, 1, 2, 3}}, {"sha256", NULL, {0, 1, 2, 3}}}, sizeof(t_crypt) * SSL_CRYPT_NB);
	ft_memcpy(ssl.flags_all, (struct s_flag[]){{"-p", 0, 0, NULL, NULL}, {"-q", 0, 0, NULL, NULL}, {"-r", 0, 0, NULL, NULL}, {"-s", 0, 0, NULL, fn_arg_s }}, sizeof(t_flag) * SSL_FLAG_NB);
	ssl.args = args;
	ssl.verbose = verbose;
	if (*args)
	{
		if (!parse_args(&ssl, ssl.args) && ssl.verbose)
		{
			print_error(&ssl);
			return (NULL);
		}
	}
	else
	{
		if (!handle_shell(&ssl) && ssl.verbose)
		{
			print_error(&ssl);
			return (NULL);
		}
	}
	if (ssl.crypt)
	{
		// print_inputs(&ssl);
		ssl.crypt->func(&ssl);
		free_inputs(&ssl);
		return (ssl.res);
	}
	return (NULL);
}

int			main(int ac, char **av)
{
	char	*ret;

	ret = ft_ssl(++av, 1);
	if (!ret)
	{
		if (ac == 1)
			ft_printf(SSL_USAGE_EMPTY_ARG);
		return (1);
	}
	return (0);
}
