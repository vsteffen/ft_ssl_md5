/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools_64.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 17:41:59 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 17:42:01 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint64_t	swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8)
		& 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16)
		& 0x0000FFFF0000FFFFULL);
	return ((val << 32) | (val >> 32));
}

uint64_t	rot_r_64(uint64_t x, int8_t n)
{
	return (((x) >> (n)) | ((x) << (64 - (n))));
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
