#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include "libft.h"
# include <fcntl.h>

# define BUFF_STDIN 2047

# define FLAG_NB 4
# define FLAG_MAX_PER_CRYPT 4

/*
**	FLAGS TAB
*/
# define FLAG_P 0
# define FLAG_Q 1
# define FLAG_R 2
# define FLAG_S 3

/*
**	[0] -> -p, echo STDIN to STDOUT and append the checksum to STDOUT
**	[1] -> -q, quiet mode
**	[2] -> -r, reverse the format of the output.
**	[3] -> -s, print the sum of the given string
*/

# define CRYPT_NB 2

# define USAGE "Standard commands:\n\nMessage Digest commands:\nmd5\nsha256\n\nCipher commands:\n"

# define INVALID_ARG "ft_ssl: Error: '%s' is an invalid command.\n"
# define INVALID_FLAG "ft_ssl: Error: option '%s' requires an argument\n"
# define INVALID_STDIN "ft_ssl: standard input: Bad file descriptor\n"

typedef struct		s_input {
	char			*data;
	size_t			len;
	char			*filename;
	int				fd;
	struct s_input	*next;
}					t_input;

struct				s_ssl;

typedef int8_t		(t_fn_flag)(struct s_ssl *ssl, void *data);
typedef int8_t		(t_fn_crypt)(struct s_ssl *ssl);

typedef struct		s_flag {
	const char		*name;
	int8_t			type;
	int8_t			uniq;
	int8_t			enable;
	void			*data;
	t_fn_flag		*func;
}					t_flag;

typedef struct		s_crypt {
	const char		*name;
	t_fn_crypt		*func;
	int8_t			flags[FLAG_MAX_PER_CRYPT];
}					t_crypt;

typedef struct		s_ssl {
	char			*res;
	int8_t			verbose;
	char			**args;
	t_flag			flags_all[FLAG_NB];
	t_crypt			crypts[CRYPT_NB];
	t_crypt			*crypt;
	t_input			*inputs;
	uint8_t			cur_arg;
	const char		*error;
	const char		*error_more_1;
	const char		*error_more_2;
	const char		*error_more_3;
	int8_t			error_no_usage;
}					t_ssl;

int8_t				parse_args(t_ssl *ssl, char **args);
int8_t				handle_shell(t_ssl *ssl);

int8_t				fn_arg_s(t_ssl *ssl, void *data);

t_input				*create_input(void *data, char *filename, size_t len);
void				add_input(t_ssl *ssl, t_input *new_input);
void				add_input_first(t_ssl *ssl, t_input *new_input);
void				free_inputs(t_ssl *ssl);

void				print_inputs(t_ssl *ssl);

int8_t				handle_md5(t_ssl *ssl);

#endif
