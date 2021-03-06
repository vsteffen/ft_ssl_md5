/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/03 21:53:30 by vsteffen          #+#    #+#             */
/*   Updated: 2019/06/03 21:53:31 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include "libft.h"
# include <fcntl.h>
# include <sys/errno.h>
# include <sys/stat.h>

# include "ft_md5.h"
# include "ft_sha_2.h"

# define SSL_BUFF 2048

# define SSL_FLAG_NB 4
# define SSL_FLAG_MAX_PER_CRYPT 4

# define SSL_FLAG_P 0
# define SSL_FLAG_Q 1
# define SSL_FLAG_R 2
# define SSL_FLAG_S 3

/*
**	[0] -> -p, echo STDIN to STDOUT and append the checksum to STDOUT
**	[1] -> -q, quiet mode
**	[2] -> -r, reverse the format of the output.
**	[3] -> -s, print the sum of the given string
*/

# define SSL_CRYPT_NB 5
# define SSL_USAGE_COMMAND "Standard commands:\n\n"
# define SSL_USAGE_DIGEST_1 "Message Digest commands:\n"
# define SSL_USAGE_DIGEST_2 "md5\t\tsha224\t\tsha256\t\tsha384\t\tsha512\n\n"
# define SSL_USAGE_DIGEST SSL_USAGE_DIGEST_1 SSL_USAGE_DIGEST_2
# define SSL_USAGE_CYPHER "Cipher commands:\n"
# define SSL_USAGE_LIST_CMD SSL_USAGE_COMMAND SSL_USAGE_DIGEST SSL_USAGE_CYPHER
# define SSL_USAGE_ARG "Usage: ft_ssl command [command opts] [command args]\n"
# define SSL_USAGE SSL_USAGE_ARG SSL_USAGE_LIST_CMD
# define SSL_USAGE_ARG_SHELL "Usage: command [command opts] [command args]\n"
# define SSL_USAGE_SHELL SSL_USAGE_ARG_SHELL SSL_USAGE_LIST_CMD

# define SSL_SHELL_PROMPT "ft_ssl> "

# define SSL_INVALID_ARG "ft_ssl: Error: '%s' is an invalid command.\n"
# define SSL_INVALID_FLAG "ft_ssl: Error: option '%s' requires an argument\n"
# define SSL_INVALID_STDIN "ft_ssl: standard input: Bad file descriptor\n"
# define SSL_INVALID_FILE_ERRNO "ft_ssl: %s: %s\n"
# define SSL_INVALID_FILE_ISDIR "ft_ssl: %s: Is a directory\n"
# define SSL_INVALID_SHELL "Invalid command '%s'; type \"help\" for a list.\n"

typedef struct		s_ssl_in {
	char			*data;
	size_t			len;
	char			*filename;
	int				fd;
	int8_t			is_stdin;
	struct s_ssl_in	*next;
}					t_ssl_in;

struct s_ssl;

typedef int8_t		(t_fn_flag)(struct s_ssl *ssl, void *data);
typedef int8_t		(t_fn_crypt)(struct s_ssl *ssl);

typedef struct		s_ssl_flag {
	const char		*name;
	int8_t			uniq;
	int8_t			enable;
	void			*data;
	t_fn_flag		*func;
}					t_ssl_flag;

typedef struct		s_ssl_crypt {
	const char		*name;
	t_fn_crypt		*func;
	int8_t			flags[SSL_FLAG_MAX_PER_CRYPT];
}					t_ssl_crypt;

typedef struct		s_ssl {
	char			**res;
	int8_t			verbose;
	char			**args;
	t_ssl_flag		flags_all[SSL_FLAG_NB];
	t_ssl_crypt		crypts[SSL_CRYPT_NB];
	t_ssl_crypt		*crypt;
	t_ssl_in		*inputs;
	uint8_t			inputs_nb;
	uint8_t			cur_arg;
	char			*error;
	const char		*error_more_1;
	const char		*error_more_2;
	const char		*error_more_3;
	int8_t			error_no_usage;
}					t_ssl;

int8_t				parse_args(t_ssl *ssl, char **args);
int8_t				get_ssl_in_stdin(t_ssl *ssl);

int8_t				handle_shell(t_ssl *ssl);
int8_t				shell_compare(const char *cmd, const char *input);

void				print_error(t_ssl *ssl);
void				print_error_and_reset(t_ssl *ssl);

int8_t				fn_arg_s(t_ssl *ssl, void *data);

t_ssl_in			*create_input(char *data, char *filename, size_t len,
	int8_t is_stdin);
void				add_input(t_ssl *ssl, t_ssl_in *new_input);
void				add_input_first(t_ssl *ssl, t_ssl_in *new_input);
void				free_inputs(t_ssl *ssl);

void				print_ssl_ins(t_ssl *ssl);
void				print_bloc(uint8_t *bloc, size_t size);

void				dtoa_hex_ptr(char *ptr, uintmax_t nb, size_t prec,
	int8_t flag_upper);
void				free_array_str(char **res);
int					ssl_open_file(t_ssl *ssl, t_ssl_in *input);

uint32_t			swap_uint32(uint32_t val);
uint64_t			swap_uint64(uint64_t val);
void				reverse_endian_array_32(uint32_t *array, size_t length);
void				reverse_endian_array_64(uint64_t *array, size_t length);
uint32_t			rot_r_32(uint32_t x, int8_t n);
uint64_t			rot_r_64(uint64_t x, int8_t n);

#endif
