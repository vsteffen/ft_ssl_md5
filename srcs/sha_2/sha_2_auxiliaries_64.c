/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_2_auxiliaries_64.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint64_t	sha_2_sig_up_0_64(uint64_t x)
{
	return (rot_r_64(x, 28) ^ rot_r_64(x, 34) ^ rot_r_64(x, 39));
}

uint64_t	sha_2_sig_up_1_64(uint64_t x)
{
	return (rot_r_64(x, 14) ^ rot_r_64(x, 18) ^ rot_r_64(x, 41));
}

uint64_t	sha_2_sig_low_0_64(uint64_t x)
{
	return (rot_r_64(x, 1) ^ rot_r_64(x, 8) ^ (x >> 7));
}

uint64_t	sha_2_sig_low_1_64(uint64_t x)
{
	return (rot_r_64(x, 19) ^ rot_r_64(x, 61) ^ (x >> 6));
}
