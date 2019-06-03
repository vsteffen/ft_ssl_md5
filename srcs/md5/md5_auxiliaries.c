/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_auxiliaries.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint32_t		md5_f(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) | ((~x) & z));
}

uint32_t		md5_g(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & z) | (y & (~z)));
}

uint32_t		md5_h(uint32_t x, uint32_t y, uint32_t z)
{
	return (x ^ y ^ z);
}

uint32_t		md5_i(uint32_t x, uint32_t y, uint32_t z)
{
	return (y ^ (x | (~z)));
}

uint32_t		md5_rotate_left(uint32_t x, int8_t n)
{
	return (((x) << (n)) | ((x) >> (32 - (n))));
}
