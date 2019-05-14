#include "ft_ssl_md5.h"

void		sha_2_fill_msg_schedule_64(uint64_t sch[80], uint8_t *bloc)
{
	int8_t		i;

	i = 0;
	while (i < 16)
	{
		sch[i] = *(uint64_t *)(bloc + i * sizeof(uint64_t));
		i++;
	}
	while (i < 80)
	{
		sch[i] = sha_2_sig_low_1_32(sch[i - 2]) + sch[i - 7] + sha_2_sig_low_0_32(sch[i - 15]) + sch[i - 16];
		i++;
	}
}

void		sha_2_rounds_64(t_sha_2_w_64 *w, uint8_t *bloc, uint64_t t[65])
{
	t_sha_2_w_64	w_tmp;
	uint64_t		sch[80];
	int8_t			i;

	(void)w;
	(void)w_tmp;
	(void)bloc;
	(void)t;
	(void)i;
	sha_2_fill_msg_schedule_64(sch, bloc);
	// i = 0;
	// while (i < 16)
	// {
	// 	x[i] = *(uint64_t *)(bloc + 4 * i);
	// 	i++;
	// }
	// tmp.a = words->a;
	// tmp.b = words->b;
	// tmp.c = words->c;
	// tmp.d = words->d;
	// md5_round_1(words, x, t);
	// md5_round_2(words, x, t);
	// md5_round_3(words, x, t);
	// md5_round_4(words, x, t);
	// words->a = words->a + tmp.a;
	// words->b = words->b + tmp.b;
	// words->c = words->c + tmp.c;
	// words->d = words->d + tmp.d;
}