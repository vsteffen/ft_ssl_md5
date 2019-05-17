#include "ft_ssl_md5.h"

int8_t	flag_detected(t_ssl *ssl, char *flag_name)
{
	int8_t		i;

	i = -1;
	while (++i < SSL_FLAG_NB)
		if (ft_strcmp(ssl->flags_all[i].name, flag_name) == 0)
			return (i);
	ssl->error = SSL_INVALID_ARG;
	ssl->error_more_1 = flag_name;
	return (-1);
}

int8_t	add_flag(t_ssl *ssl, int8_t flag_i)
{
	int8_t	i;

	i = -1;
	while (++i < SSL_FLAG_MAX_PER_CRYPT)
	{
		if (ssl->crypt->flags[i] == flag_i)
		{
			if (ssl->flags_all[i].uniq && ssl->flags_all[i].enable)
			{
				ssl->error = SSL_INVALID_ARG;
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
	add_input(ssl, create_input(NULL, arg, 0, 0));
	return (1);
}

t_crypt	*search_crypt(t_ssl *ssl, const char *name_given)
{
	int8_t		i;

	i = -1;
	while (++i < SSL_CRYPT_NB)
		if (ft_strcmp(ssl->crypts[i].name, name_given) == 0)
			return (&(ssl->crypts[i]));
	return (NULL);
}

int8_t	get_inputs_in_stdin(t_ssl *ssl)
{
	char	*stdin_str;
	char	*tmp;
	char	buff[SSL_BUFF + 1];
	size_t	ret_read;
	size_t	len;

	stdin_str = ft_strdup("");
	len = 0;
	while ((ret_read = read(0, buff, SSL_BUFF)) > 0)
	{
		buff[ret_read] = '\0';
		tmp = (char *)malloc(sizeof(char) * (len + ret_read + 1));
		ft_memcpy(tmp, stdin_str, len);
		ft_memcpy(tmp + len, buff, ret_read + 1);
		free(stdin_str);
		stdin_str = tmp;
		len += ret_read;
	}
	if (ret_read == (size_t)-1)
	{
		free(stdin_str);
		return (0);
	}
	add_input_first(ssl, create_input(stdin_str, NULL, len, 1));
	return (1);
}

int8_t	parse_args(t_ssl *ssl, char **args)
{
	int8_t	must_be_file;

	if (*args)
		if (!(ssl->crypt = search_crypt(ssl, *args)))
		{
			ssl->error = SSL_INVALID_ARG;
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
	if (!ssl->inputs || ssl->flags_all[SSL_FLAG_P].enable)
		return (get_inputs_in_stdin(ssl));
	return (1);
}