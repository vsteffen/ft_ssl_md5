#include "ft_ssl_md5.h"

uint32_t		md5_f(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) | (~x & z));
}

uint32_t		md5_g(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) | (y & (~z)));
}

uint32_t		md5_h(uint32_t x, uint32_t y, uint32_t z)
{
	return (x ^ y ^ z);
}

uint32_t		md5_i(uint32_t x, uint32_t y, uint32_t z)
{
	return (y ^ (x | (~z)));
}

uint32_t		md5_rotate_left(uint32_t x, int8_t n)
{
	return (((x) << (n)) | ((x) >> (32 - (n))));
}