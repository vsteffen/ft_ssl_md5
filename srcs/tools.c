#include "ft_ssl_md5.h"

static void		fill_zero(size_t length, char *ptr)
{
	if (length > 0)
	{
		while (--length > 0)
			ptr[length] = '0';
		ptr[0] = '0';
	}
}

void			dtoa_hex_ptr(char *ptr, uintmax_t nb, size_t prec, int8_t flag_upper)
{
	char		*alph;
	size_t		length;

	if (nb == 0)
		return ((void)ft_strcpy(ptr, "0"));
	length = (size_t)count_numeral_base(nb, 16);
	if (length < prec)
		length = prec;
	ptr[length] = '\0';
	if (flag_upper)
		alph = "0123456789ABCDEF";
	else
		alph = "0123456789abcdef";
	while (nb != 0)
	{
		length--;
		ptr[length] = alph[nb % 16];
		nb /= 16;
	}
	fill_zero(length, ptr);
}