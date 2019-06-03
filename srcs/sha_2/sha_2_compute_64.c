/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_2_compute_64.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 15:01:52 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 15:02:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		sha_2_fill_msg_schedule_64(uint64_t sch[80], uint8_t *bloc)
{
	int8_t		i;

	i = 0;
	while (i < 16)
	{
		sch[i] = swap_uint64(*(uint64_t *)(bloc + i * sizeof(uint64_t)));
		i++;
	}
	while (i < 80)
	{
		sch[i] = sha_2_sig_low_1_64(sch[i - 2]) + sch[i - 7] + sha_2_sig_low_0_64(sch[i - 15]) + sch[i - 16];
		i++;
	}
}

void	sha_2_compute_64(t_sha_2_w_64 *h, uint8_t *bloc, uint64_t k[80])
{
	t_sha_2_w_64	w_tmp;
	uint64_t		sch[80];
	int8_t			t;
	uint64_t		t1;
	uint64_t		t2;

	sha_2_fill_msg_schedule_64(sch, bloc);
	ft_memcpy(&w_tmp, h, sizeof(t_sha_2_w_64));
	t = 0;
	while (t < 80)
	{
	
		t1 = w_tmp.h + sha_2_sig_up_1_64(w_tmp.e) + sha_2_ch_64(w_tmp.e, w_tmp.f, w_tmp.g) + k[t] + sch[t];
		t2 = sha_2_sig_up_0_64(w_tmp.a) + sha_2_maj_64(w_tmp.a, w_tmp.b, w_tmp.c);
		w_tmp.h = w_tmp.g;
		w_tmp.g = w_tmp.f;
		w_tmp.f = w_tmp.e;
		w_tmp.e = w_tmp.d + t1;
		w_tmp.d = w_tmp.c;
		w_tmp.c = w_tmp.b;
		w_tmp.b = w_tmp.a;
		w_tmp.a = t1 + t2;
		t++;
	}
	h->a = w_tmp.a + h->a;
	h->b = w_tmp.b + h->b;
	h->c = w_tmp.c + h->c;
	h->d = w_tmp.d + h->d;
	h->e = w_tmp.e + h->e;
	h->f = w_tmp.f + h->f;
	h->g = w_tmp.g + h->g;
	h->h = w_tmp.h + h->h;
}
