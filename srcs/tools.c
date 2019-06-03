/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static void	fill_zero(size_t length, char *ptr)
{
	if (length > 0)
	{
		while (--length > 0)
			ptr[length] = '0';
		ptr[0] = '0';
	}
}

void		dtoa_hex_ptr(char *ptr, uintmax_t nb, size_t prec, int8_t flag_upper)
{
	char		*alph;
	size_t		length;

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

void		free_array_str(char **array)
{
	uint8_t		i;

	i = 0;
	if (!array)
		return ;
	while (array[i])
	{
		free(array[i]);
		i++;
	}
	free(array);
}

void		print_error_and_reset(t_ssl *ssl)
{
	print_error(ssl);
	ssl->error = NULL;
	ssl->error_more_1 = NULL;
	ssl->error_more_2 = NULL;
	ssl->error_more_3 = NULL;
}

uint32_t	swap_uint32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return ((val << 16) | (val >> 16));
}

uint64_t	swap_uint64(uint64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return ((val << 32) | (val >> 32));
}

uint32_t	rot_r_32(uint32_t x, int8_t n)
{
	return (((x) >> (n)) | ((x) << (32 - (n))));
}

uint64_t	rot_r_64(uint64_t x, int8_t n)
{
	return (((x) >> (n)) | ((x) << (64 - (n))));
}

void		reverse_endian_array_32(uint32_t *array, size_t length)
{
	size_t	i;

	i = 0;
	while (i < length)
	{
		array[i] = swap_uint32(array[i]);
		i++;
	}
}

void		reverse_endian_array_64(uint64_t *array, size_t length)
{
	size_t	i;

	i = 0;
	while (i < length)
	{
		array[i] = swap_uint64(array[i]);
		i++;
	}
}




