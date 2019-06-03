/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_md5.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 20:17:49 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 20:17:51 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_MD5_H
# define FT_MD5_H

# define SSL_BUFF_MD5 64

struct s_ssl;
struct s_ssl_in;

typedef struct		s_md5_file {
	int				fd;
	uint8_t			buff[SSL_BUFF_MD5];
	uint8_t			ret_read;
}					t_md5_file;

typedef struct		s_md5 {
	struct s_ssl	*ssl;
	uint8_t			digest[16];
	uint32_t		t[65];
	t_md5_file		file;
}					t_md5;

typedef struct		s_md5_words {
	uint32_t		a;
	uint32_t		b;
	uint32_t		c;
	uint32_t		d;
}					t_md5_words;

int8_t				handle_md5(struct s_ssl *ssl);
int8_t				handle_md5_file(t_md5 *md5, struct s_ssl_in *input);
int8_t				handle_md5_raw(t_md5 *md5, struct s_ssl_in *input);
void				md5_update(uint8_t *bloc, t_md5 *md5);
void				md5_padding_length(uint8_t *bloc, size_t total_len);

void				md5_compute(t_md5_words *words, uint8_t *bloc,
	uint32_t t[65]);
void				md5_round_1(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_2(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_3(t_md5_words *w, uint32_t x[16], uint32_t t[65]);
void				md5_round_4(t_md5_words *w, uint32_t x[16], uint32_t t[65]);

uint32_t			md5_f(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_g(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_h(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_i(uint32_t x, uint32_t y, uint32_t z);
uint32_t			md5_rtl(uint32_t x, int8_t shift);

#endif
