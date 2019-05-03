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
		ft_printf(USAGE);
}

char		*ft_ssl(char **args, int8_t verbose)
{
	struct s_ssl	ssl;

	ft_bzero(&ssl, sizeof(t_ssl));
	ft_memcpy(ssl.crypts, (t_crypt[]){{"md5", handle_md5, {0, 1, 2, 3}}, {"sha256", NULL, {0, 1, 2, 3}}}, sizeof(t_crypt) * CRYPT_NB);
	ft_memcpy(ssl.flags_all, (t_flag[]){{.name = "-p"}, {.name = "-q"}, {.name = "-r"}, {.name = "-s", .func = fn_arg_s }}, sizeof(t_flag) * FLAG_NB);
	ssl.args = args;
	ssl.verbose = verbose;
	if (*args)
	{
		if (!parse_args(&ssl, ssl.args) && ssl.verbose)
			print_error(&ssl);
	}
	else
	{
		if (!handle_shell(&ssl) && ssl.verbose)
			print_error(&ssl);
	}
	print_inputs(&ssl);
	return (ssl.res);
}

int			main(int ac, char **av)
{
	char	*ret;

	(void)ac;
	ret = ft_ssl(++av, 1);
	if (!ret)
		return (1);
	return (0);
}
