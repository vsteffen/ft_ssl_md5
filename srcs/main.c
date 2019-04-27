#include "ft_ssl_md5.h"

int			print_usage(const char *error)
{
	ft_printf(USAGE, error);
	return (1);
}

int			main(int ac, char **av)
{
	struct s_ssl	ssl;
	t_crypt crypts[2] = {{.name = "md5", .flags = {0, 1, 2, 3}}, {.name = "sha256", .flags = {0, 1, 2, 3}}};
	t_flag flags[4] = {{.name = "-p"}, {.name = "-q"}, {.name = "-r"}, {.name = "-s"}};

	ssl.crypts = crypts;
	ssl.flags_all = flags;
	if (ac > 1)
	{
		if (!parse_args(&ssl, ++av))
			return (print_usage(ssl.arg_error));
	}
	else
	{
		if (!handle_shell(&ssl))
			return (print_usage(ssl.arg_error));
	}
	return (0);
}
