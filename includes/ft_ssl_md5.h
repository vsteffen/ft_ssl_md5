#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include "libft.h"

typedef struct		s_input {
	int8_t			*data;
	char			*filename;
	int				fd;
	struct s_input	*next;
}					t_input;

typedef struct		s_ssl {
	int8_t			args[4];
	//  0 -> -p, echo STDIN to STDOUT and append the checksum to STDOUT
	//  1 -> -q, quiet mode
	//  2 -> -r, reverse the format of the output.
	//  3 -> -s, print the sum of the given string
	t_input			*inputs;
}					t_ssl;

int8_t				parse_args(t_ssl *ssl, int ac, char **av);
int8_t				handle_shell(t_ssl *ssl);

#endif
