#include "ft_ssl_md5.h"

int8_t	fn_arg_s(t_ssl *ssl, void *data)
{
	(void)data;
	if (ssl->args[ssl->cur_arg + 1])
	{
		ssl->cur_arg++;
		ft_printf("String to hash -> [%s]\n", ssl->args[ssl->cur_arg]);
	}
	else
	{
		ssl->arg_error = INVALID_FLAG;
		ssl->arg_error_more_1 = ssl->args[ssl->cur_arg];
		return (0);
	}
	return (1);
}