/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools_32.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 17:41:55 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 17:41:56 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint32_t	swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return ((val << 16) | (val >> 16));
}

uint32_t	rot_r_32(uint32_t x, int8_t n)
{
	return (((x) >> (n)) | ((x) << (32 - (n))));
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
