#include "ft_ssl_md5.h"

int			print_usage(t_ssl *ssl)
{
	if (ssl->arg_error_more_3)
		ft_printf(ssl->arg_error, ssl->arg_error_more_1, ssl->arg_error_more_2, ssl->arg_error_more_3);
	else if (ssl->arg_error_more_2)
		ft_printf(ssl->arg_error, ssl->arg_error_more_1, ssl->arg_error_more_2);
	else if (ssl->arg_error_more_1)
		ft_printf(ssl->arg_error, ssl->arg_error_more_1);
	ft_printf(USAGE);
	return (1);
}

int			main(int ac, char **av)
{
	struct s_ssl	ssl;

	ft_bzero(&ssl, sizeof(t_ssl));
	t_crypt crypts[2] = {{.name = "md5", .flags = {0, 1, 2, 3}}, {.name = "sha256", .flags = {0, 1, 2, 3}}};
	t_flag flags[4] = {{.name = "-p"}, {.name = "-q"}, {.name = "-r"}, {.name = "-s", .func = fn_arg_s }};

	ssl.crypts = crypts;
	ssl.flags_all = flags;
	ssl.args = ++av;
	if (ac > 1)
	{
		if (!parse_args(&ssl, ssl.args))
			return (print_usage(&ssl));
	}
	else
	{
		if (!handle_shell(&ssl))
			return (print_usage(&ssl));
	}
	return (0);
}
