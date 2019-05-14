#include "ft_ssl_md5.h"

void		sha_2_fill_msg_schedule_32(uint32_t sch[64], uint8_t *bloc)
{
	int8_t		i;

	i = 0;
	while (i < 16)
	{
		sch[i] = *(uint32_t *)(bloc + i * sizeof(uint32_t));
		i++;
	}
	while (i < 64)
	{
		sch[i] = sha_2_sig_low_1_32(sch[i - 2]) + sch[i - 7] + sha_2_sig_low_0_32(sch[i - 15]) + sch[i - 16];
		i++;
	}
}

void	sha_2_rounds_32(t_sha_2_w_32 *w, uint8_t *bloc, uint32_t k[64])
{
	t_sha_2_w_32	w_tmp;
	uint32_t		sch[64];
	int8_t			i;
	uint32_t		t1_tmp;
	uint32_t		t2_tmp;

	sha_2_fill_msg_schedule_32(sch, bloc);
	ft_memcpy(&w_tmp, w, sizeof(t_sha_2_w_32));
	// print_bloc((uint8_t *)&w_tmp, sizeof(t_sha_2_w_32));
	i = 0;
	while (i < 64)
	{
		t1_tmp = w_tmp.h + sha_2_sig_up_1_32(w_tmp.e) + sha_2_ch_32(w_tmp.e, w_tmp.f, w_tmp.g) + k[i] + sch[i];
		t2_tmp = sha_2_sig_up_0_32(w_tmp.a) + sha_2_maj_32(w_tmp.a, w_tmp.b, w_tmp.c);
		w_tmp.h = w_tmp.g;
		w_tmp.g = w_tmp.f;
		w_tmp.f = w_tmp.e;
		w_tmp.e = w_tmp.d + t1_tmp;
		w_tmp.d = w_tmp.c;
		w_tmp.c = w_tmp.b;
		w_tmp.b = w_tmp.a;
		w_tmp.a = t1_tmp + t2_tmp;
		i++;
	}
	w->a = w->a + w_tmp.a;
	w->b = w->b + w_tmp.b;
	w->c = w->c + w_tmp.c;
	w->d = w->d + w_tmp.d;
	w->e = w->e + w_tmp.e;
	w->f = w->f + w_tmp.f;
	w->g = w->g + w_tmp.g;
	w->h = w->h + w_tmp.h;
}