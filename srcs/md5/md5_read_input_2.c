/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_read_input_2.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 20:11:29 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 20:11:30 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		md5_update(uint8_t *bloc, t_md5 *md5)
{
	t_md5_words		*words;

	words = (t_md5_words *)(md5->digest);
	md5_compute(words, bloc, md5->t);
}

void		md5_padding_length(uint8_t *bloc, size_t total_len)
{
	*(uint64_t *)(bloc + 56) = (uint64_t)total_len << 3;
}
