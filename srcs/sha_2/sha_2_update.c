/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_2_update.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 21:47:23 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 21:47:24 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		sha_2_update_32(t_sha_2 *sha_2, uint8_t *bloc)
{
	t_sha_2_w_32		*h;

	h = (t_sha_2_w_32 *)(sha_2->digest);
	sha_2_compute_32(h, bloc, (uint32_t *)(sha_2->k));
}

void		sha_2_update_64(t_sha_2 *sha_2, uint8_t *bloc)
{
	t_sha_2_w_64		*h;

	h = (t_sha_2_w_64 *)(sha_2->digest);
	sha_2_compute_64(h, bloc, (sha_2->k));
}

void		sha_2_update(t_sha_2 *sha_2, uint8_t *bloc)
{
	if (sha_2->type < 2)
		sha_2_update_32(sha_2, bloc);
	else
		sha_2_update_64(sha_2, bloc);
}

void		sha_2_padding_length(uint8_t *bloc, size_t total_len,
	t_sha_2 *sha_2)
{
	*(uint64_t *)(bloc + (sha_2->buff_size - 8)) = swap_uint64(
		(uint64_t)total_len << 3);
}
