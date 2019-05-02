#include "ft_ssl_md5.h"

int			print_error(t_ssl *ssl)
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
			return (print_error(&ssl));
	}
	else
	{
		if (!handle_shell(&ssl))
			return (print_error(&ssl));
	}
	print_inputs(&ssl);
	return (0);
}
