#include "ft_ssl_md5.h"

int			main(int ac, char **av)
{
	struct s_ssl	ssl;

	if (ac > 1)
	{
		if (!parse_args(&ssl, ac, av))
			return (1);
	}
	else
	{
		if (!handle_shell(&ssl))
			return (1);
	}
	return (0);
}
