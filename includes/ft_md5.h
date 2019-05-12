#ifndef FT_MD5_H
# define FT_MD5_H

# define SSL_BUFF_MD5 64

struct				s_ssl;

typedef struct		s_md5_words {
	uint32_t		a;
	uint32_t		b;
	uint32_t		c;
	uint32_t		d;
}					t_md5_words;

int8_t				handle_md5(struct s_ssl *ssl);

void				md5_rounds(t_md5_words *words, uint8_t *bloc, uint32_t t[65]);
void				md5_round_1(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_2(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_3(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_4(t_md5_words *w, uint32_t x[16], uint32_t t[65]);

uint32_t			md5_f(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_g(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_h(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_i(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_rotate_left(uint32_t x, int8_t shift);

#endif