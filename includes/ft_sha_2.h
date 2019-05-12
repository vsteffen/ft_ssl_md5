#ifndef FT_SHA_2_H
# define FT_SHA_2_H

# define SSL_DIGEST_SHA_224 56
# define SSL_DIGEST_SHA_256 64
# define SSL_DIGEST_SHA_384 96
# define SSL_DIGEST_SHA_512 128

# define SSL_BUFF_SHA_32 64
# define SSL_BUFF_SHA_64 128

struct				s_ssl;

typedef struct		s_sha_2_w_32 {
	uint32_t		a;
	uint32_t		b;
	uint32_t		c;
	uint32_t		d;
	uint32_t		e;
	uint32_t		f;
	uint32_t		g;
	uint32_t		h;
}					t_sha_2_w_32;

typedef struct		s_sha_2_w_64 {
	uint64_t		a;
	uint64_t		b;
	uint64_t		c;
	uint64_t		d;
	uint64_t		e;
	uint64_t		f;
	uint64_t		g;
	uint64_t		h;
}					t_sha_2_w_64;

/*
**	sha_2.type
**	
**	0 -> sha224
**	1 -> sha256
**	2 -> sha384
**	3 -> sha512
*/

# define SSL_TYPE_SHA_224 0
# define SSL_TYPE_SHA_256 1
# define SSL_TYPE_SHA_384 2
# define SSL_TYPE_SHA_512 3

typedef struct		s_sha_2 {
	struct s_ssl	*ssl;
	int8_t			type;
	int8_t			is_32_w;
	uint8_t			buff_size;
	uint8_t			digest_size;
}					t_sha_2;

int8_t				handle_sha_2(struct s_ssl *ssl);

void				sha_2_rounds(t_sha_2_w_32 *words, uint8_t *bloc, uint32_t t[64]);
void				sha_2_round_1(t_sha_2_w_32 *w, uint32_t x[16], uint32_t t[64]);
void				sha_2_round_2(t_sha_2_w_32 *w, uint32_t x[16], uint32_t t[64]);
void				sha_2_round_3(t_sha_2_w_32 *w, uint32_t x[16], uint32_t t[64]);
void				sha_2_round_4(t_sha_2_w_32 *w, uint32_t x[16], uint32_t t[64]);

uint32_t			sha_2_f(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_g(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_h(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_i(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_rotate_left(uint32_t x, int8_t shift);

#endif