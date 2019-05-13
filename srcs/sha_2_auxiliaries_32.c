#include "ft_ssl_md5.h"

uint32_t	sha_2_ch_32(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint32_t	sha_2_maj_32(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint32_t	sha_2_sig_up_0_32(uint32_t x)
{
	return (rot_r_32(x, 2) ^ rot_r_32(x, 13) ^ rot_r_32(x, 22));
}

uint32_t	sha_2_sig_up_1_32(uint32_t x)
{
	return (rot_r_32(x, 6) ^ rot_r_32(x, 11) ^ rot_r_32(x, 25));
}

uint32_t	sha_2_sig_low_0_32(uint32_t x)
{
	return (rot_r_32(x, 7) ^ rot_r_32(x, 18) ^ shift_r_32(x, 3));
}

uint32_t	sha_2_sig_low_1_32(uint32_t x)
{
	return (rot_r_32(x, 17) ^ rot_r_32(x, 19) ^ shift_r_32(x, 10));
}