#include "ft_ssl_md5.h"

void	md5_rounds(t_md5_words *words, uint8_t *bloc)
{
	t_md5_words		tmp;
	uint32_t		x[16];
	uint32_t 		t[65];
	int8_t			i;

	ft_memcpy(&t, (uint32_t[]){ 0x0,
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391}, 65 * sizeof(uint32_t));
	i = 0;
	while (i < 16)
	{
		x[i] = *(uint32_t *)(bloc + 4 * i);
		i++;
	}
	tmp.a = words->a;
	tmp.b = words->b;
	tmp.c = words->c;
	tmp.d = words->d;
	md5_round_1(words, x, t);
	md5_round_2(words, x, t);
	md5_round_3(words, x, t);
	md5_round_4(words, x, t);
	words->a = words->a + tmp.a;
	words->b = words->b + tmp.b;
	words->c = words->c + tmp.c;
	words->d = words->d + tmp.d;
}

void	md5_round_1(t_md5_words *w, uint32_t x[16], uint32_t t[65])
{
	w->a = w->b + md5_rotate_left((w->a + md5_f(w->b, w->c, w->d) + x[0] + t[1]), 7);
	w->d = w->a + md5_rotate_left((w->d + md5_f(w->a, w->b, w->c) + x[1] + t[2]), 12);
	w->c = w->d + md5_rotate_left((w->c + md5_f(w->d, w->a, w->b) + x[2] + t[3]), 17);
	w->b = w->c + md5_rotate_left((w->b + md5_f(w->c, w->d, w->a) + x[3] + t[4]), 22);
	w->a = w->b + md5_rotate_left((w->a + md5_f(w->b, w->c, w->d) + x[4] + t[5]), 7);
	w->d = w->a + md5_rotate_left((w->d + md5_f(w->a, w->b, w->c) + x[5] + t[6]), 12);
	w->c = w->d + md5_rotate_left((w->c + md5_f(w->d, w->a, w->b) + x[6] + t[7]), 17);
	w->b = w->c + md5_rotate_left((w->b + md5_f(w->c, w->d, w->a) + x[7] + t[8]), 22);
	w->a = w->b + md5_rotate_left((w->a + md5_f(w->b, w->c, w->d) + x[8] + t[9]), 7);
	w->d = w->a + md5_rotate_left((w->d + md5_f(w->a, w->b, w->c) + x[9] + t[10]), 12);
	w->c = w->d + md5_rotate_left((w->c + md5_f(w->d, w->a, w->b) + x[10] + t[11]), 17);
	w->b = w->c + md5_rotate_left((w->b + md5_f(w->c, w->d, w->a) + x[11] + t[12]), 22);
	w->a = w->b + md5_rotate_left((w->a + md5_f(w->b, w->c, w->d) + x[12] + t[13]), 7);
	w->d = w->a + md5_rotate_left((w->d + md5_f(w->a, w->b, w->c) + x[13] + t[14]), 12);
	w->c = w->d + md5_rotate_left((w->c + md5_f(w->d, w->a, w->b) + x[14] + t[15]), 17);
	w->b = w->c + md5_rotate_left((w->b + md5_f(w->c, w->d, w->a) + x[15] + t[16]), 22);
}

void	md5_round_2(t_md5_words *w, uint32_t x[16], uint32_t t[65])
{
	w->a = w->b + md5_rotate_left((w->a + md5_g(w->b, w->c, w->d) + x[1] + t[17]), 5);
	w->d = w->a + md5_rotate_left((w->d + md5_g(w->a, w->b, w->c) + x[6] + t[18]), 9);
	w->c = w->d + md5_rotate_left((w->c + md5_g(w->d, w->a, w->b) + x[11] + t[19]), 14);
	w->b = w->c + md5_rotate_left((w->b + md5_g(w->c, w->d, w->a) + x[0] + t[20]), 20);
	w->a = w->b + md5_rotate_left((w->a + md5_g(w->b, w->c, w->d) + x[5] + t[21]), 5);
	w->d = w->a + md5_rotate_left((w->d + md5_g(w->a, w->b, w->c) + x[10] + t[22]), 9);
	w->c = w->d + md5_rotate_left((w->c + md5_g(w->d, w->a, w->b) + x[15] + t[23]), 14);
	w->b = w->c + md5_rotate_left((w->b + md5_g(w->c, w->d, w->a) + x[4] + t[24]), 20);
	w->a = w->b + md5_rotate_left((w->a + md5_g(w->b, w->c, w->d) + x[9] + t[25]), 5);
	w->d = w->a + md5_rotate_left((w->d + md5_g(w->a, w->b, w->c) + x[14] + t[26]), 9);
	w->c = w->d + md5_rotate_left((w->c + md5_g(w->d, w->a, w->b) + x[3] + t[27]), 14);
	w->b = w->c + md5_rotate_left((w->b + md5_g(w->c, w->d, w->a) + x[8] + t[28]), 20);
	w->a = w->b + md5_rotate_left((w->a + md5_g(w->b, w->c, w->d) + x[13] + t[29]), 5);
	w->d = w->a + md5_rotate_left((w->d + md5_g(w->a, w->b, w->c) + x[2] + t[30]), 9);
	w->c = w->d + md5_rotate_left((w->c + md5_g(w->d, w->a, w->b) + x[7] + t[31]), 14);
	w->b = w->c + md5_rotate_left((w->b + md5_g(w->c, w->d, w->a) + x[12] + t[32]), 20);
}

void	md5_round_3(t_md5_words *w, uint32_t x[16], uint32_t t[65])
{
	w->a = w->b + md5_rotate_left((w->a + md5_h(w->b, w->c, w->d) + x[5] + t[33]), 4);
	w->d = w->a + md5_rotate_left((w->d + md5_h(w->a, w->b, w->c) + x[8] + t[34]), 11);
	w->c = w->d + md5_rotate_left((w->c + md5_h(w->d, w->a, w->b) + x[11] + t[35]), 16);
	w->b = w->c + md5_rotate_left((w->b + md5_h(w->c, w->d, w->a) + x[14] + t[36]), 23);
	w->a = w->b + md5_rotate_left((w->a + md5_h(w->b, w->c, w->d) + x[1] + t[37]), 4);
	w->d = w->a + md5_rotate_left((w->d + md5_h(w->a, w->b, w->c) + x[4] + t[38]), 11);
	w->c = w->d + md5_rotate_left((w->c + md5_h(w->d, w->a, w->b) + x[7] + t[39]), 16);
	w->b = w->c + md5_rotate_left((w->b + md5_h(w->c, w->d, w->a) + x[10] + t[40]), 23);
	w->a = w->b + md5_rotate_left((w->a + md5_h(w->b, w->c, w->d) + x[13] + t[41]), 4);
	w->d = w->a + md5_rotate_left((w->d + md5_h(w->a, w->b, w->c) + x[0] + t[42]), 11);
	w->c = w->d + md5_rotate_left((w->c + md5_h(w->d, w->a, w->b) + x[3] + t[43]), 16);
	w->b = w->c + md5_rotate_left((w->b + md5_h(w->c, w->d, w->a) + x[6] + t[44]), 23);
	w->a = w->b + md5_rotate_left((w->a + md5_h(w->b, w->c, w->d) + x[9] + t[45]), 4);
	w->d = w->a + md5_rotate_left((w->d + md5_h(w->a, w->b, w->c) + x[12] + t[46]), 11);
	w->c = w->d + md5_rotate_left((w->c + md5_h(w->d, w->a, w->b) + x[15] + t[47]), 16);
	w->b = w->c + md5_rotate_left((w->b + md5_h(w->c, w->d, w->a) + x[2] + t[48]), 23);
}

void	md5_round_4(t_md5_words *w, uint32_t x[16], uint32_t t[65])
{
	w->a = w->b + md5_rotate_left((w->a + md5_i(w->b, w->c, w->d) + x[0] + t[49]), 6);
	w->d = w->a + md5_rotate_left((w->d + md5_i(w->a, w->b, w->c) + x[7] + t[50]), 10);
	w->c = w->d + md5_rotate_left((w->c + md5_i(w->d, w->a, w->b) + x[14] + t[51]), 15);
	w->b = w->c + md5_rotate_left((w->b + md5_i(w->c, w->d, w->a) + x[5] + t[52]), 21);
	w->a = w->b + md5_rotate_left((w->a + md5_i(w->b, w->c, w->d) + x[12] + t[53]), 6);
	w->d = w->a + md5_rotate_left((w->d + md5_i(w->a, w->b, w->c) + x[3] + t[54]), 10);
	w->c = w->d + md5_rotate_left((w->c + md5_i(w->d, w->a, w->b) + x[10] + t[55]), 15);
	w->b = w->c + md5_rotate_left((w->b + md5_i(w->c, w->d, w->a) + x[1] + t[56]), 21);
	w->a = w->b + md5_rotate_left((w->a + md5_i(w->b, w->c, w->d) + x[8] + t[57]), 6);
	w->d = w->a + md5_rotate_left((w->d + md5_i(w->a, w->b, w->c) + x[15] + t[58]), 10);
	w->c = w->d + md5_rotate_left((w->c + md5_i(w->d, w->a, w->b) + x[6] + t[59]), 15);
	w->b = w->c + md5_rotate_left((w->b + md5_i(w->c, w->d, w->a) + x[13] + t[60]), 21);
	w->a = w->b + md5_rotate_left((w->a + md5_i(w->b, w->c, w->d) + x[4] + t[61]), 6);
	w->d = w->a + md5_rotate_left((w->d + md5_i(w->a, w->b, w->c) + x[11] + t[62]), 10);
	w->c = w->d + md5_rotate_left((w->c + md5_i(w->d, w->a, w->b) + x[2] + t[63]), 15);
	w->b = w->c + md5_rotate_left((w->b + md5_i(w->c, w->d, w->a) + x[9] + t[64]), 21);
}