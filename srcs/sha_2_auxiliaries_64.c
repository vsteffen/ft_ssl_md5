#include "ft_ssl_md5.h"

uint64_t	sha_2_ch_64(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint64_t	sha_2_maj_64(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint64_t	sha_2_sig_up_0_64(uint64_t x)
{
	return (rot_r_64(x, 28) ^ rot_r_64(x, 34) ^ rot_r_64(x, 39));
}

uint64_t	sha_2_sig_up_1_64(uint64_t x)
{
	return (rot_r_64(x, 14) ^ rot_r_64(x, 18) ^ rot_r_64(x, 41));
}

uint64_t	sha_2_sig_low_0_64(uint64_t x)
{
	return (rot_r_64(x, 1) ^ rot_r_64(x, 8) ^ shift_r_64(x, 7));
}

uint64_t	sha_2_sig_low_1_64(uint64_t x)
{
	return (rot_r_64(x, 19) ^ rot_r_64(x, 61) ^ shift_r_64(x, 6));
}