#include "ft_ssl_md5.h"

int8_t	flag_detected(t_ssl *ssl, char *flag_name)
{
	int8_t		i;

	i = -1;
	while (++i < FLAG_NB)
		if (ft_strcmp(ssl->flags_all[i].name, flag_name) == 0)
			return (i);
	ssl->error = INVALID_ARG;
	ssl->error_more_1 = flag_name;
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
			{
				ssl->error = INVALID_ARG;
				ssl->error_more_1 = ssl->flags_all[i].name;
				return (0);
			}
			ssl->flags_all[i].enable = 1;
			if (ssl->flags_all[i].func)
				return (ssl->flags_all[i].func(ssl, NULL));
			return (1);
		}
	}
	return (0);
}

int8_t	detect_and_handle_arg(t_ssl *ssl, char *arg, int8_t *must_be_file)
{
	int8_t	ret_flag;

	if (!*must_be_file)
	{
		if (ft_strcmp(arg, "--") == 0)
		{
			*must_be_file = 1;
			return (1);
		}
		else if (arg[0] == '-' && arg[1])
		{
			if ((ret_flag = flag_detected(ssl, arg)) == -1)
				return (0);
			if (!add_flag(ssl, ret_flag))
				return (0);
			return (1);
		}
	}
	*must_be_file = 1;
	add_input(ssl, create_input(NULL, arg, 0));
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

int8_t	get_inputs_in_stdin(t_ssl *ssl)
{
	char	stdin_buff[BUFF_STDIN + 1];
	char	*data;
	size_t	len;
	int		ret;

	data = ft_strdup("");
	len = 0;
	while ((ret = read(0, stdin_buff, BUFF_STDIN)) > 0)
	{
		stdin_buff[ret] = '\0';
		data = ft_strjoinaf1(data, stdin_buff);
		len += ret;
	}
	if (ret == -1)
	{
		ssl->error = INVALID_STDIN;
		ssl->error_no_usage = 1;
		return (0);
	}
	add_input_first(ssl, create_input(data, NULL, len));
	if (ssl->flags_all[FLAG_P].enable)
		ft_putstr(data);
	return (1);
}

int8_t	parse_args(t_ssl *ssl, char **args)
{
	int8_t	must_be_file;

	if (*args)
		if (!(ssl->crypt = search_crypt(ssl, *args)))
		{
			ssl->error = INVALID_ARG;
			ssl->error_more_1 = args[ssl->cur_arg];
			return (0);
		}
	ssl->cur_arg = 1;
	must_be_file = 0;
	while (args[ssl->cur_arg])
	{
		if (!detect_and_handle_arg(ssl, args[ssl->cur_arg], &must_be_file))
			return(0);
		ssl->cur_arg++;
	}
	if (!ssl->inputs || ssl->flags_all[FLAG_P].enable)
		return (get_inputs_in_stdin(ssl));
	return (1);
}