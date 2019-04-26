#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include "libft.h"

typedef struct		s_elem {
	struct s_elem	*prec;
	struct s_elem	*next;
}					t_elem;

typedef struct		s_ssl_md5 {
	t_elem			*elem;
	t_elem			*current;
	t_elem			*last;
}					t_ssl_md5;

#endif
