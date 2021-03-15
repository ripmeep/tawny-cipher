#include <stdio.h>
#include <string.h>
#include <stdbool.h>


#define TAWNY_DEBUG 0  //DEBUG MODE 1 = DEBUG OUTPUT
		       //	    0 = NO DEBUG OUTPUT

#ifdef TAWNY_BLOCK_SIZE
#undef TAWNY_BLOCK_SIZE
#endif

#ifdef TAWNY_BLOCK_SIZE_BYTES
#undef TAWNY_BLOCK_SIZE_BYTES
#endif

#ifdef TAWNY_KEY_LENGTH
#undef TAWNY_KEY_LENGTH
#endif

#ifdef TAWNY_KEY_LENGTH_BYTES
#undef TAWNY_KEY_LENGTH_BYTES
#endif

#ifdef TAWNY_IV_LENGTH
#undef TAWNY_IV_LENGTH
#endif

#ifdef TAWNY_IV_LENGTH_BYTES
#undef TAWNY_IV_LENGTH_BYTES
#endif

#define TAWNY_BLOCK_SIZE 256
#define TAWNY_BLOCK_SIZE_BYTES TAWNY_BLOCK_SIZE / 8

#define TAWNY_KEY_LENGTH       256
#define TAWNY_KEY_LENGTH_BYTES TAWNY_KEY_LENGTH / 8

#define TAWNY_IV_LENGTH 256
#define TAWNY_IV_LENGTH_BYTES TAWNY_IV_LENGTH / 8

#define TAWNY_UPDATE_IV         1
#define TAWNY_UPDATE_KEY        2
#define TAWNY_UPDATE_PLAINTEXT  3
#define TAWNY_UPDATE_CIPHERTEXT 4


struct TawnyMatrix {
      	size_t rows;
      	size_t columns;
      	int table[4][8];
};

typedef struct __TAWNY_CTX {
      	size_t key_len;
      	size_t iv_len;

      	unsigned char * plaintext;
      	size_t plaintext_len;

      	unsigned char key[TAWNY_KEY_LENGTH_BYTES];
      	unsigned char iv[TAWNY_IV_LENGTH_BYTES];

      	struct TawnyMatrix matrix;

      	unsigned char keyround[TAWNY_BLOCK_SIZE_BYTES];

      	unsigned char * ciphertext;
      	size_t ciphertext_len;
} Tawny_CTX;


void Tawny_Hexdump(const char * s, size_t len, size_t row_len, int show_chars, int colors) {
    int b = 0;
    int xc_offset = 0;
    int cw = 0;
    int is_printable = 0;

    for (int i = 0; i < len; ++i) {
        if (b%row_len == 0)
            printf("[%04x]\t", i);

        if ((isalpha(s[i]) || ispunct(s[i]) || isdigit(s[i])) && colors > 0) {
            is_printable = 1;
            printf("\033[01;9%dm", colors);
        } else
            is_printable = 0;

        printf("%02X\033[0m ", s[i] & 0xFF);

        b++;

//      if (b == row_len/2)
//          printf("  ");

        if (b%row_len == 0 || i + 1 == len) {
            if (show_chars) {
                for (int p = 0; p < (3*row_len) - (3*b); ++p)
                    printf(" ");

                printf("\t| ");

                if (i + 1 == len)
                    xc_offset = ((i - row_len) + 1) + (row_len - b);
                else
                    xc_offset = (i - row_len) + 1;

                cw = 0;
                for (int x = xc_offset; x < i + 1; ++x) {
                    if (isalpha(s[x]) || ispunct(s[x]) || isdigit(s[x]))
                        if ((int)s[x] == 0x20)
                            printf(".");
                        else {
                            if ((isalpha(s[x]) || ispunct(s[x]) || isdigit(s[x])) && colors > 0)
                                printf("\033[01;9%dm", colors);
                            printf("%c\033[0m", s[x]);
                        }
                    else
                        printf(".");
                    cw++;
                }


                for (int p = 0; p < (row_len - cw); ++p)
                    printf(" ");

                printf(" |");
            }

            printf("\n");
            b = 0;
        }
    }

    printf("\n");
}

/* PCSS#7 PADDING EXTENSION FOR COMPLETING BLOCKS */
unsigned char * pkcs7pad(unsigned char * buf, size_t buf_len, size_t block_size) {
      	int n = ((block_size - buf_len) % block_size);

      	if (n == 0)
            	n = block_size;

      	unsigned char * s = (unsigned char *)malloc(buf_len + n);

      	memcpy(s, buf, buf_len + n);

      	for (int i = 0; i < n; ++i) {
            	s[buf_len + i] = (char)n;
      	}

      	return s;
}

size_t xor(unsigned char * md, size_t smd, unsigned char * buf1, size_t s1, unsigned char * buf2, size_t s2) {
      	size_t sz = 0;
      	size_t wz = 0;

      	if (s1 > smd || s2 > smd)
            	return 0;

      	if (s1 > s2)
            	wz = s2;
      	else
            	wz = s1;

      	for (size_t i = 0; i < wz; ++i) {
            	md[i] = buf1[i]^buf2[i];
            	sz++;
      	}

      	return sz;
}

void show_matrix(struct TawnyMatrix * m) {
      	for (int r = 0; r < 4; ++r) {
            	printf("[  ");

            	for (int c = 0; c < 8; ++c) {
                  	printf("%02x  ", m->table[r][c] & 0xFF);
            	}

            	printf(" ]\n");
      	}
}

void Tawny_Init(Tawny_CTX * ctx) {
/* EMPTY CONTEXT STRUCT */

      	ctx->key_len            = 0;
      	ctx->iv_len             = 0;
      	ctx->plaintext_len      = 0;
      	ctx->ciphertext_len     = 0;
      	ctx->matrix.rows        = 4;
      	ctx->matrix.columns     = 8;

      	memset(ctx->key, '\0', sizeof(ctx->key));
      	memset(ctx->iv, '\0', sizeof(ctx->iv));
}

int Tawny_Update(int mode, Tawny_CTX * ctx, unsigned char * iv, unsigned char * key, unsigned char * plaintext, unsigned char * ciphertext, size_t plaintext_len, size_t ciphertext_len) {
      	int status = 0;

/* UPDATE INITIALIZATION VECTOR */

      	if (mode == TAWNY_UPDATE_IV) {
            	size_t ctx_iv_size = sizeof(ctx->iv);

            	for (size_t i = 0; i < ctx_iv_size; ++i)
                  	ctx->iv[i] = iv[i];

            	status = 1;

            	for (size_t i = 0; i < ctx_iv_size; ++i) {
                  	if (iv[i] != ctx->iv[i]) {
                        	status = 0;
                        	break;
                  	}
            	}

            	if (status)
                  	ctx->iv_len = ctx_iv_size;

      	}

/* UPDATE KEY */

      	else if (mode == TAWNY_UPDATE_KEY) {
            	size_t ctx_key_size = sizeof(ctx->key);

            	for (size_t i = 0; i < ctx_key_size; ++i)
                  	ctx->key[i] = key[i];

            	status = 1;

            	for (size_t i = 0; i < ctx_key_size; ++i) {
                  	if (key[i] != ctx->key[i]) {
                        	status = 0;
                        	break;
                  	}
            	}

            	if (status)
                  	ctx->key_len = ctx_key_size;

      	}

/* UPDATE PLAINTEXT */

      	else if (mode == TAWNY_UPDATE_PLAINTEXT) {
            	if (plaintext_len < TAWNY_BLOCK_SIZE_BYTES)
                  	return 0;

		ctx->plaintext = plaintext;

		status = 1;

		for (size_t i = 0; i < plaintext_len; ++i) {
			if (plaintext[i] != ctx->plaintext[i]) {
				status = 0;
				break;
			}
		}

            	if (status)
                  	ctx->plaintext_len = plaintext_len;
      	}

/* UPDATE CIPHERTEXT */

      	else if (mode == TAWNY_UPDATE_CIPHERTEXT) {
	    	if (ciphertext_len < TAWNY_BLOCK_SIZE_BYTES)
			return 0;


	    	status = 1;

/*	    	for (size_t i = 0; i < ciphertext_len; ++i) {
	  	  	if (ciphertext[i] != ctx->ciphertext[i]) {
		        	status = 0;
		        	break;
		  	}
	    	}
*/


	    	ctx->ciphertext = malloc(ciphertext_len + 1);
	    	memcpy(ctx->ciphertext, ciphertext, ciphertext_len);

//	    	if (status) {
		  	ctx->ciphertext_len = ciphertext_len;
//	    	}

      	}


      	else {
            	;
      	}

      	return status;
}


unsigned int Tawny_Encrypt(Tawny_CTX * ctx) {
/* INITIALIZE MATRIX TABLE */

      	for (size_t r = 0; r < ctx->matrix.rows; ++r) {
            	for (size_t c = 0; c < ctx->matrix.columns; ++c) {
                  	ctx->matrix.table[r][c] = 022;
            	}
      	}

/* CHECK IV, KEY AND PLAINTEXT EXIST IN STRUCT */

      	if (ctx->iv_len == 0 || ctx->key_len == 0 || ctx->plaintext_len == 0)
            	return -1;

/* XOR KEY AND INITIALIZATION VECTOR FOR FIRST KEYROUND */

      	if (!xor(ctx->keyround, sizeof(ctx->keyround), ctx->key, ctx->key_len, ctx->iv, ctx->iv_len))
            	return -1;

      // static unsigned char sbox[256] = { 0x8e, 0xaa, 0x51, 0x13, 0x81, 0x30, 0x28, 0xb5, 0x82, 0x8a, 0x4f, 0x29, 0x6a, 0x06, 0xcd, 0xa6,
      //                           0x54, 0xd7, 0xb7, 0x3f, 0x91, 0x1a, 0xfc, 0x7c, 0xac, 0x6d, 0x90, 0xb2, 0xc2, 0x25, 0xd8, 0x39,
      //                           0x2e, 0x15, 0xf5, 0xfb, 0xfe, 0x68, 0x05, 0xa1, 0x6c, 0x97, 0x6f, 0x99, 0x26, 0x4a, 0x3e, 0x1e,
      //                           0x9e, 0x61, 0xf6, 0x71, 0xb6, 0x2c, 0x36, 0xd9, 0xfd, 0xff, 0x44, 0xfa, 0x32, 0x55, 0x19, 0x35,
      //                           0xb1, 0x48, 0xa7, 0xcb, 0xf3, 0xec, 0xa3, 0xf2, 0x5e, 0x4d, 0x09, 0x59, 0xce, 0x6b, 0xe0, 0xab,
      //                           0xde, 0x7e, 0x69, 0x77, 0x85, 0x0e, 0xdc, 0x52, 0x9d, 0x62, 0x78, 0xbe, 0x8d, 0xd0, 0x2a, 0x1d,
      //                           0xa8, 0xf7, 0x23, 0x86, 0x8f, 0x3d, 0xea, 0x9a, 0xad, 0xe9, 0x5d, 0x42, 0x66, 0x31, 0xe7, 0x7a,
      //                           0x00, 0x72, 0xc7, 0x5f, 0x93, 0x34, 0x38, 0xda, 0xd6, 0xf9, 0x2b, 0xa2, 0x5a, 0xbc, 0x37, 0x94,
      //                           0x11, 0x64, 0xb0, 0xbd, 0x4c, 0x20, 0x9f, 0x95, 0xb9, 0x3b, 0x02, 0xed, 0xa9, 0x47, 0x88, 0xe6,
      //                           0x04, 0xd5, 0xdd, 0xee, 0xc1, 0x96, 0xe5, 0x14, 0x50, 0xeb, 0x84, 0x0a, 0x27, 0xd3, 0x56, 0x63,
      //                           0x87, 0x16, 0xaf, 0x24, 0x8b, 0x83, 0x4b, 0x9c, 0x40, 0xd1, 0x22, 0x10, 0x2d, 0x5c, 0xc6, 0x45,
      //                           0x03, 0x60, 0x65, 0x21, 0x6e, 0xe1, 0xf8, 0x33, 0xae, 0x70, 0x07, 0x57, 0x7f, 0x0d, 0x2f, 0x53,
      //                           0xef, 0x76, 0x80, 0xb4, 0x0f, 0xdb, 0xf1, 0x79, 0xe2, 0x4e, 0x9b, 0xa4, 0xcc, 0x7d, 0x43, 0xbb,
      //                           0xbf, 0xc9, 0x8c, 0x0c, 0xba, 0xc4, 0xc8, 0x08, 0xe4, 0xb3, 0x49, 0xe8, 0xf4, 0xb8, 0xd4, 0x12,
      //                           0x98, 0x01, 0x5b, 0x17, 0x1b, 0xa0, 0x75, 0x7b, 0x89, 0xf0, 0x58, 0x41, 0x46, 0xc0, 0x67, 0x1c,
      //                           0x74, 0xcf, 0xd2, 0x18, 0x3c, 0xe3, 0x3a, 0xc5, 0xdf, 0x1f, 0x0b, 0xca, 0xa5, 0xc3, 0x73, 0x92 };

/* CREATE FUNC LOCAL VARIABLES TO LIMIT STRUCT ACCESS */

      	size_t plaintext_len = (size_t)ctx->plaintext_len;
      	size_t block_size = TAWNY_BLOCK_SIZE_BYTES;
      	size_t nmemb = plaintext_len / block_size;
      	size_t total_size = ((sizeof(unsigned char) * TAWNY_BLOCK_SIZE_BYTES) * nmemb);
      	size_t matrix_columns = ctx->matrix.columns;
      	size_t matrix_rows = ctx->matrix.rows;
      	size_t pos = 0;

      	char c_plaintext_block[TAWNY_BLOCK_SIZE_BYTES];

      	ctx->ciphertext = (unsigned char*)malloc(total_size);

      	for (int e = 0; e < nmemb; ++e) { /* REPEAT ROUNDS FOR N BLOCKS OF PADDED PLAINTEXT */

/* COPY "PLAINTEXT" INTO OTHER SECTION OF MEMORY FOR FUNC */

            	memset(c_plaintext_block, '\0', sizeof(c_plaintext_block));
            	memcpy(c_plaintext_block, ctx->plaintext + (block_size * e), sizeof(c_plaintext_block));

/* XOR CURRENT KEYROUND & "PLAINTEXT" MEMORY -> "PLAINTEXT" */

            	if (!xor((unsigned char*)c_plaintext_block, sizeof(c_plaintext_block), ctx->keyround, TAWNY_KEY_LENGTH_BYTES, (unsigned char*)c_plaintext_block, sizeof(c_plaintext_block))) {
                  	break;
            	}

/* FILL MATRIX TABLE WITH RESULT */

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	for (size_t c = 0; c < matrix_columns; ++c) {
                        	pos = c + (r * matrix_columns);
                        	ctx->matrix.table[r][c] = (int)c_plaintext_block[pos];
                        	ctx->keyround[pos] = c_plaintext_block[pos];
                  	}
            	}

//R3
//R4
//R1
//R2

//SHIFT COLUMNS TO LEFT BY 1

/* ROTATE MATRIX TABLE USING VALUES ABOVE */

            	int val;

            	for (size_t c = 0; c < matrix_columns; ++c) {
                  	val = ctx->matrix.table[0][c];
                  	ctx->matrix.table[0][c] = ctx->matrix.table[2][c];
                  	ctx->matrix.table[2][c] = val;
            	}

            	for (size_t c = 0; c < matrix_columns; ++c) {
                  	val = ctx->matrix.table[1][c];
                  	ctx->matrix.table[1][c] = ctx->matrix.table[3][c];
                  	ctx->matrix.table[3][c] = val;
            	}

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	val = ctx->matrix.table[r][0];
                  	ctx->matrix.table[r][0] = ctx->matrix.table[r][7];
                  	ctx->matrix.table[r][7] = val;

                  	val = ctx->matrix.table[r][1];
                  	ctx->matrix.table[r][1] = ctx->matrix.table[r][6];
                  	ctx->matrix.table[r][6] = val;

                  	val = ctx->matrix.table[r][2];
                  	ctx->matrix.table[r][2] = ctx->matrix.table[r][5];
                  	ctx->matrix.table[r][5] = val;

                  	val = ctx->matrix.table[r][3];
                  	ctx->matrix.table[r][3] = ctx->matrix.table[r][4];
                  	ctx->matrix.table[r][4] = val;
            	}

/* EXPORT ROTATED MATRIX TABLE INTO "CIPHERTEXT" MEMORY */

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	for (size_t c = 0; c < matrix_columns; ++c) {
                        	pos = c + (r * matrix_columns);
                        	ctx->ciphertext[(block_size * e) + pos] = (unsigned char)ctx->matrix.table[r][c] & 0xFF;
                        	ctx->ciphertext_len++;
                  	}
            	}
      	}

//      for (size_t i = 0; i < total_size; ++i) {
//	  buf[i] = ctx->ciphertext[i];
//      }

      	ctx->ciphertext[total_size] = '\0';

/* RETURN BYTES WRITTEN */
	return total_size;
}




unsigned int Tawny_Decrypt(Tawny_CTX * ctx) {
/* CHECK IV, KEY AND CIPHERTEXT EXIST IN STRUCT */

      	if (ctx->iv_len == 0 || ctx->key_len == 0 || ctx->ciphertext_len == 0)
            	return -1;

/* XOR KEY & INITIALIZATION VECTOR FOR FIRST KEYROUND */

      	if (!xor(ctx->keyround, sizeof(ctx->keyround), ctx->key, ctx->key_len, ctx->iv, ctx->iv_len))
            	return -1;

      // static unsigned char rbox[256] = { 0x8e, 0xaa, 0x51, 0x13, 0x81, 0x30, 0x28, 0xb5, 0x82, 0x8a, 0x4f, 0x29, 0x6a, 0x06, 0xcd, 0xa6,
      //                           0x54, 0xd7, 0xb7, 0x3f, 0x91, 0x1a, 0xfc, 0x7c, 0xac, 0x6d, 0x90, 0xb2, 0xc2, 0x25, 0xd8, 0x39,
      //                           0x2e, 0x15, 0xf5, 0xfb, 0xfe, 0x68, 0x05, 0xa1, 0x6c, 0x97, 0x6f, 0x99, 0x26, 0x4a, 0x3e, 0x1e,
      //                           0x9e, 0x61, 0xf6, 0x71, 0xb6, 0x2c, 0x36, 0xd9, 0xfd, 0xff, 0x44, 0xfa, 0x32, 0x55, 0x19, 0x35,
      //                           0xb1, 0x48, 0xa7, 0xcb, 0xf3, 0xec, 0xa3, 0xf2, 0x5e, 0x4d, 0x09, 0x59, 0xce, 0x6b, 0xe0, 0xab,
      //                           0xde, 0x7e, 0x69, 0x77, 0x85, 0x0e, 0xdc, 0x52, 0x9d, 0x62, 0x78, 0xbe, 0x8d, 0xd0, 0x2a, 0x1d,
      //                           0xa8, 0xf7, 0x23, 0x86, 0x8f, 0x3d, 0xea, 0x9a, 0xad, 0xe9, 0x5d, 0x42, 0x66, 0x31, 0xe7, 0x7a,
      //                           0x00, 0x72, 0xc7, 0x5f, 0x93, 0x34, 0x38, 0xda, 0xd6, 0xf9, 0x2b, 0xa2, 0x5a, 0xbc, 0x37, 0x94,
      //                           0x11, 0x64, 0xb0, 0xbd, 0x4c, 0x20, 0x9f, 0x95, 0xb9, 0x3b, 0x02, 0xed, 0xa9, 0x47, 0x88, 0xe6,
      //                           0x04, 0xd5, 0xdd, 0xee, 0xc1, 0x96, 0xe5, 0x14, 0x50, 0xeb, 0x84, 0x0a, 0x27, 0xd3, 0x56, 0x63,
      //                           0x87, 0x16, 0xaf, 0x24, 0x8b, 0x83, 0x4b, 0x9c, 0x40, 0xd1, 0x22, 0x10, 0x2d, 0x5c, 0xc6, 0x45,
      //                           0x03, 0x60, 0x65, 0x21, 0x6e, 0xe1, 0xf8, 0x33, 0xae, 0x70, 0x07, 0x57, 0x7f, 0x0d, 0x2f, 0x53,
      //                           0xef, 0x76, 0x80, 0xb4, 0x0f, 0xdb, 0xf1, 0x79, 0xe2, 0x4e, 0x9b, 0xa4, 0xcc, 0x7d, 0x43, 0xbb,
      //                           0xbf, 0xc9, 0x8c, 0x0c, 0xba, 0xc4, 0xc8, 0x08, 0xe4, 0xb3, 0x49, 0xe8, 0xf4, 0xb8, 0xd4, 0x12,
      //                           0x98, 0x01, 0x5b, 0x17, 0x1b, 0xa0, 0x75, 0x7b, 0x89, 0xf0, 0x58, 0x41, 0x46, 0xc0, 0x67, 0x1c,
      //                           0x74, 0xcf, 0xd2, 0x18, 0x3c, 0xe3, 0x3a, 0xc5, 0xdf, 0x1f, 0x0b, 0xca, 0xa5, 0xc3, 0x73, 0x92 };

/* INITIALIZE MATRIX TABLE */

      	for (size_t r = 0; r < ctx->matrix.rows; ++r) {
	  	for (size_t c = 0; c < ctx->matrix.columns; ++c) {
			ctx->matrix.table[r][c] = 022;
	  	}
      	}

      	size_t ciphertext_len = (size_t)ctx->ciphertext_len;
      	size_t block_size = TAWNY_BLOCK_SIZE_BYTES;
      	size_t nmemb = ciphertext_len / block_size;
      	size_t total_size = ((sizeof(unsigned char) * TAWNY_BLOCK_SIZE_BYTES) * nmemb);
      	size_t matrix_columns = ctx->matrix.columns;
      	size_t matrix_rows = ctx->matrix.rows;
      	size_t pos = 0;

      	char c_ciphertext_block[TAWNY_BLOCK_SIZE_BYTES];

      	ctx->plaintext = malloc(total_size);


      	for (int d = 0; d < nmemb; ++d) {
	  	memset(c_ciphertext_block, '\0', sizeof(c_ciphertext_block));
		memcpy(c_ciphertext_block, ctx->ciphertext + (block_size * d), sizeof(c_ciphertext_block));

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	for (size_t c = 0; c < matrix_columns; ++c) {
                        	pos = c + (r * matrix_columns);
                        	ctx->matrix.table[r][c] = (int)c_ciphertext_block[pos];
//                      	ctx->keyround[pos] = c_ciphertext_block[pos];
                  	}
            	}

//R1
//R2
//R3
//R4

//SHIFT COLUMNS TO RIGHT BY 1

/* UNROTATE MATRIX TABLE USING VALUES ABOVE */

            	int val;

            	for (size_t c = 0; c < matrix_columns; ++c) {
                  	val = ctx->matrix.table[2][c];
                  	ctx->matrix.table[2][c] = ctx->matrix.table[0][c];
                  	ctx->matrix.table[0][c] = val;
            	}

            	for (size_t c = 0; c < matrix_columns; ++c) {
                  	val = ctx->matrix.table[3][c];
                  	ctx->matrix.table[3][c] = ctx->matrix.table[1][c];
                  	ctx->matrix.table[1][c] = val;
            	}

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	val = ctx->matrix.table[r][7];
                  	ctx->matrix.table[r][7] = ctx->matrix.table[r][0];
                  	ctx->matrix.table[r][0] = val;

                  	val = ctx->matrix.table[r][6];
                  	ctx->matrix.table[r][6] = ctx->matrix.table[r][1];
                  	ctx->matrix.table[r][1] = val;

                  	val = ctx->matrix.table[r][5];
                  	ctx->matrix.table[r][5] = ctx->matrix.table[r][2];
                  	ctx->matrix.table[r][2] = val;

                  	val = ctx->matrix.table[r][4];
                  	ctx->matrix.table[r][4] = ctx->matrix.table[r][3];
                  	ctx->matrix.table[r][3] = val;
            	}

/* EXPORT UNROTATED MATRIX TABLE INTO "CIPHERTEXT" MEMORY */

            	for (size_t r = 0; r < matrix_rows; ++r) {
                  	for (size_t c = 0; c < matrix_columns; ++c) {
                        	pos = c + (r * matrix_columns);
                        	c_ciphertext_block[pos] = (unsigned char)ctx->matrix.table[r][c] & 0xFF;
                  	}
            	}


/* XOR CURRENT KEYROUND & "PLAINTEXT" MEMORY -> "PLAINTEXT" */

            	if (!xor((unsigned char*)c_ciphertext_block, sizeof(c_ciphertext_block), ctx->keyround, TAWNY_KEY_LENGTH_BYTES, (unsigned char*)c_ciphertext_block, sizeof(c_ciphertext_block))) {
                  	break;
            	}

	  	for (size_t i = 0; i < block_size; ++i) {
			ctx->plaintext_len++;
			ctx->plaintext[i + (block_size * d)] = c_ciphertext_block[i];
	  	}

          	if (!xor(ctx->keyround, sizeof(ctx->keyround), ctx->keyround, TAWNY_KEY_LENGTH_BYTES, (unsigned char*)c_ciphertext_block, sizeof(c_ciphertext_block))) {
			break;
		}

      	}

/* REVERSE PKCS#7 PADDING ON LAST BLOCK OF PLAITEXT */

	int p = (int)ctx->plaintext[ctx->plaintext_len - 1];

	ctx->plaintext[ctx->plaintext_len - p] = '\0';
	ctx->plaintext_len = ctx->plaintext_len - p;


	return ctx->plaintext_len;
}

