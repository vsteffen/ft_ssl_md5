#include "ft_ssl_md5.h"


void	md5_rounds(t_md5_words *words, uint8_t *bloc)
{
	(void)bloc;
	(void)words;
}

// 	t_md5_words		buff;
// 	uint32_t		tmp_a;
// 	int8_t			i;
// 	int8_t			j;

// 	i = 0;
// 	while (i < 64)
// 	{

// 	}
// }
// /* Process each 16-word block. */
// For i = 0 to N/16-1 do

//     /* Copy block i into X. */
//     For j = 0 to 15 do
//         Set X[j] to M[i*16+j].
//     end /* of loop on j */

//     /* Save A as AA, B as BB, C as CC, and D as DD. */
//     AA = A
//     BB = B
//     CC = C
//     DD = D

//     /* Round 1. */
//     /* Let [abcd k s i] denote the operation
//         a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
//     /* Do the following 16 operations. */
//     [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
//     [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
//     [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
//     [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]

//     /* Round 2. */
//     /* Let [abcd k s i] denote the operation
//         a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
//     /* Do the following 16 operations. */
//     [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
//     [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
//     [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
//     [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]

//     /* Round 3. */
//     /* Let [abcd k s t] denote the operation
//         a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
//     /* Do the following 16 operations. */
//     [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
//     [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
//     [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
//     [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]

//     /* Round 4. */
//     /* Let [abcd k s t] denote the operation
//         a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
//     /* Do the following 16 operations. */
//     [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
//     [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
//     [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
//     [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]

//     /* Then perform the following additions. (That is increment each
//         of the four registers by the value it had before this block
//         was started.) */
//     A = A + AA
//     B = B + BB
//     C = C + CC
//     D = D + DD

// end /* of loop on i */