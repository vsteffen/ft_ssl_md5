/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha_2.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 21:51:43 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 21:51:44 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SHA_2_H
# define FT_SHA_2_H

# define SSL_TYPE_SHA_224 0
# define SSL_TYPE_SHA_256 1
# define SSL_TYPE_SHA_384 2
# define SSL_TYPE_SHA_512 3

# define SSL_DIGEST_SHA_224 56
# define SSL_DIGEST_SHA_256 64
# define SSL_DIGEST_SHA_384 96
# define SSL_DIGEST_SHA_512 128

# define SSL_BUFF_SHA_32 64
# define SSL_BUFF_SHA_64 128

# define SSL_PADDING_LENGTH_SHA_32 8
# define SSL_PADDING_LENGTH_SHA_64 16

struct s_ssl;
struct s_ssl_in;

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

typedef struct		s_sha_2_file {
	int				fd;
	uint8_t			buff[SSL_BUFF_SHA_64];
	uint8_t			ret_read;
}					t_sha_2_file;

typedef struct		s_sha_2 {
	struct s_ssl	*ssl;
	int8_t			type;
	uint8_t			buff_size;
	uint8_t			digest_size;
	uint8_t			padding_length;
	int8_t			padding_first_bit;
	uint64_t		digest[8];
	uint64_t		k[80];
	uint8_t			i_res;
	t_sha_2_file	file;
}					t_sha_2;

int8_t				handle_sha_2(struct s_ssl *ssl);
void				sha_2_init_digest(t_sha_2 *sha_2, uint64_t *digest);
void				sha_2_init_struct(t_sha_2 *sha_2, struct s_ssl *ssl,
	struct s_ssl_in **cur_input, int8_t *ret);
void				sha_2_update(t_sha_2 *sha_2, uint8_t *bloc);
void				sha_2_padding_length(uint8_t *bloc, size_t total_len,
	t_sha_2 *sha_2);
int8_t				handle_sha_2_file(t_sha_2 *sha_2, struct s_ssl_in *input);
int8_t				handle_sha_2_raw(t_sha_2 *sha_2, struct s_ssl_in *input);

uint32_t			sha_2_ch_32(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_maj_32(uint32_t x, uint32_t y, uint32_t z);
uint32_t			sha_2_sig_up_0_32(uint32_t x);
uint32_t			sha_2_sig_up_1_32(uint32_t x);
uint32_t			sha_2_sig_low_0_32(uint32_t x);
uint32_t			sha_2_sig_low_1_32(uint32_t x);

uint64_t			sha_2_ch_64(uint64_t x, uint64_t y, uint64_t z);
uint64_t			sha_2_maj_64(uint64_t x, uint64_t y, uint64_t z);
uint64_t			sha_2_sig_up_0_64(uint64_t x);
uint64_t			sha_2_sig_up_1_64(uint64_t x);
uint64_t			sha_2_sig_low_0_64(uint64_t x);
uint64_t			sha_2_sig_low_1_64(uint64_t x);

void				sha_2_fill_msg_schedule_32(uint32_t sch[64], uint8_t *bloc);
void				sha_2_fill_msg_schedule_64(uint64_t sch[80], uint8_t *bloc);

void				sha_2_compute_32(t_sha_2_w_32 *w, uint8_t *bloc,
	uint32_t t[65]);
void				sha_2_compute_64(t_sha_2_w_64 *w, uint8_t *bloc,
	uint64_t t[65]);

#endif
