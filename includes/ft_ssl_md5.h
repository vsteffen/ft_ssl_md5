#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include "libft.h"

# define FLAG_NB 4
# define FLAG_MAX_PER_CRYPT 4
# define CRYPT_NB 2

# define USAGE "ft_ssl: Error: '%s' is an invalid command.\nStandard commands:\n\nMessage Digest commands:\nmd5\nsha256\n\nCipher commands:\n"

typedef struct		s_input {
	int8_t			*data;
	char			*filename;
	int				fd;
	struct s_input	*next;
}					t_input;

struct				s_ssl;

typedef int8_t		(t_fn_flag)(struct s_ssl *ssl);
typedef char		*(t_fn_crypt)(struct s_ssl *ssl);

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
	t_flag			*flags_all;
	t_crypt			*crypts;
	t_crypt			*crypt;
	t_input			*inputs;
	const char		*arg_error;
}					t_ssl;

/*
**	FLAGS TAB
**	[0] -> -p, echo STDIN to STDOUT and append the checksum to STDOUT
**	[1] -> -q, quiet mode
**	[2] -> -r, reverse the format of the output.
**	[3] -> -s, print the sum of the given string
*/

int8_t				parse_args(t_ssl *ssl, char **args);
int8_t				handle_shell(t_ssl *ssl);

#endif
