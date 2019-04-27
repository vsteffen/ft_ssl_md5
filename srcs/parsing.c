#include "ft_ssl_md5.h"

int8_t	flag_detected(t_ssl *ssl, char *flag_name)
{
	int8_t		i;

	i = -1;
	while (++i < FLAG_NB)
		if (ft_strcmp(ssl->flags_all[i].name, flag_name) == 0)
			return (i);
	return (-1);
}

int8_t	add_flag(t_ssl *ssl, int8_t flag_i)
{
	int8_t	i;

	i = -1;
	while (++i < FLAG_MAX_PER_CRYPT)
	{
		if (ssl->crypt->flags[i] == flag_i)
		{
			if (ssl->flags_all[i].uniq && ssl->flags_all[i].enable)
				return (0);
			ssl->flags_all[i].enable = 1;
			return (1);
		}
	}
	return (0);
}

int8_t	detect_and_handle_arg(t_ssl *ssl, char *arg)
{
	int8_t	ret_flag;

	if (*arg == '-')
	{
		if ((ret_flag = flag_detected(ssl, arg)) == -1)
			return (0);
		if (!add_flag(ssl, ret_flag))
			return (0);
		return (1);
	}
	return (1);
}

t_crypt	*search_crypt(t_ssl *ssl, const char *name_given)
{
	int8_t		i;

	i = -1;
	while (++i < CRYPT_NB)
		if (ft_strcmp(ssl->crypts[i].name, name_given) == 0)
			return (&(ssl->crypts[i]));
	return (NULL);
}

int8_t	parse_args(t_ssl *ssl, char **args)
{
	if (*args)
		if (!(ssl->crypt = search_crypt(ssl, *args)))
			return (0);
	args++;
	while (*args)
	{
		ft_printf("%s\n", *args);
		if (!detect_and_handle_arg(ssl, *args))
		{
			ssl->arg_error = *args;
			return(0);
		}
		args++;
	}
	return (1);
}