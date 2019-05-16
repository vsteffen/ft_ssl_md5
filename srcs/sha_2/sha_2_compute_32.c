#include "ft_ssl_md5.h"

void		sha_2_fill_msg_schedule_32(uint32_t sch[64], uint8_t *bloc)
{
	int8_t		i;

	i = 0;
	while (i < 16)
	{
		sch[i] = swap_uint32(*(uint32_t *)(bloc + i * sizeof(uint32_t)));
		i++;
	}
	while (i < 64)
	{
		sch[i] = sha_2_sig_low_1_32(sch[i - 2]) + sch[i - 7] + sha_2_sig_low_0_32(sch[i - 15]) + sch[i - 16];
		i++;
	}
}

void	sha_2_compute_32(t_sha_2_w_32 *h, uint8_t *bloc, uint32_t k[64])
{
	t_sha_2_w_32	w_tmp;
	uint32_t		sch[64];
	int8_t			t;
	uint32_t		t1;
	uint32_t		t2;

	sha_2_fill_msg_schedule_32(sch, bloc);
	ft_memcpy(&w_tmp, h, sizeof(t_sha_2_w_32));
	t = 0;
	while (t < 64)
	{
	
		t1 = w_tmp.h + sha_2_sig_up_1_32(w_tmp.e) + sha_2_ch_32(w_tmp.e, w_tmp.f, w_tmp.g) + k[t] + sch[t];
		t2 = sha_2_sig_up_0_32(w_tmp.a) + sha_2_maj_32(w_tmp.a, w_tmp.b, w_tmp.c);
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