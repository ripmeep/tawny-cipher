#include "tawny.h"

#include <stdio.h>
#include <string.h>


int main(int argc, char ** argv) {
      	printf("\n\t\tSTARTING ENCRYPTION\n\n");

	int update = 0;
      	struct sha256 sha256_hash;

      	init_sha256(&sha256_hash);
      	sha256_hash.plaintext = "password";


      	if (!sha256sum(&sha256_hash)) {
            	fprintf(stderr, "Hash failed\n");

            	return -1;
      	}

//   	SHA256 IS ONLY USED AS AN EXAMPLE TO SHOW HOW THE ENCRYPTION WORKS.
//   	SHA256 PRODUCES THE CORRECT AMOUNT OF BYTES FOR THE ENCRYPTION TO WORK (32)
//   	TO KEEP THE ENCRYPTION SECURE, PLEASE USE YOUR OWN KEY GENERATED OF 32 RANDOM OR MANUAL BYTES


      	printf("SHA256 Key:\t\t");
      	print_bytes(sha256_hash.sum, SHA256_DIGEST_LENGTH);

      	unsigned char iv[TAWNY_IV_LENGTH_BYTES];

      	if (!RAND_bytes(iv, TAWNY_IV_LENGTH_BYTES)) {
            	fprintf(stderr, "Failed to generate Initialization Vector\n");
            	return -1;
      	}

      	printf("Initialization Vector:\t");
      	print_bytes(iv, sizeof(iv));

      	putchar('\n');

	unsigned char * plaintext = "hello world :) this is my home made symmetric encryption algorithm! ive been working on this for too long now rip :(";
	printf("Original plaintext length:\t[%03ld]\n", strlen((char*)plaintext));
	plaintext = pkcs7pad(plaintext, strlen(plaintext), TAWNY_BLOCK_SIZE_BYTES);

	printf("Padded plaintext length:\t[%03ld]\n", strlen((char*)plaintext));

      	Tawny_CTX ctx;
      	Tawny_Init(&ctx);


      	printf("Set IV context...        \t[%s]\n", ((update = Tawny_Update(TAWNY_UPDATE_IV, &ctx, iv, NULL, NULL, NULL, 0, 0))?"Success":"Failed"));

	if (!update)
		return -1;

      	printf("Set Key context...       \t[%s]\n", ((update = Tawny_Update(TAWNY_UPDATE_KEY, &ctx, NULL, sha256_hash.sum, NULL, NULL, 0, 0))?"Success":"Failed"));

	if (!update)
		return -1;

      	printf("Set plaintext context... \t[%s]\n", ((update = Tawny_Update(TAWNY_UPDATE_PLAINTEXT, &ctx, NULL, NULL, plaintext, NULL, strlen(plaintext), 0))?"Success":"Failed"));

	if (!update)
		return -1;


      	size_t bytes_written = Tawny_Encrypt(&ctx);

      	printf("Bytes Written:\t\t\t[%03ld]\n\n", bytes_written);

      	if (bytes_written < 0) {
		fprintf(stderr, "Encryption failed\n\n");
       	     	return -1;
      	}

      	printf("Ciphertext:        \033[01;33m\t");
      	print_bytes(ctx.ciphertext, ctx.ciphertext_len);
      	printf("\033[0mCiphertext Length: \t[%03ld]\n\n", ctx.ciphertext_len);
      	printf("\n\n\t\tSTARTING DECRYPTION\n\n");

      	unsigned char * ciphertext = ctx.ciphertext;

      	printf("SHA256 Key:\t\t");
      	print_bytes(sha256_hash.sum, SHA256_DIGEST_LENGTH);

      	memset(&ctx, 0, sizeof(ctx)); //EMPTY CONTEXT

      	Tawny_Init(&ctx);

      	printf("Initialization Vector:\t");
      	print_bytes(iv, sizeof(iv));

	putchar('\n');


      	printf("Set IV context...         \t[%s]\n",  ((update = Tawny_Update(TAWNY_UPDATE_IV, &ctx, iv, NULL, NULL, NULL, 0, 0))?"Success":"Failed"));

	if (!update)
		return -1;

      	printf("Set Key context...        \t[%s]\n",  ((update = Tawny_Update(TAWNY_UPDATE_KEY, &ctx, NULL, sha256_hash.sum, NULL, NULL, 0, 0))?"Success":"Failed"));

	if (!update)
		return -1;

      	printf("Set ciphertext context... \t[%s]\n",  ((update = Tawny_Update(TAWNY_UPDATE_CIPHERTEXT, &ctx, NULL, NULL, NULL, ciphertext, 0, bytes_written))?"Success":"Failed"));

	if (!update)
		return -1;


      	bytes_written = Tawny_Decrypt(&ctx);

      	if (bytes_written < 0) {
		fprintf(stderr, "Decryption failed\n\n");

		return -1;
      	}

      	printf("\nPlaintext:        \t\033[01;32m%s\033[0m\n", ctx.plaintext);
      	printf("Plaintext Length: \t[%03ld]\n\n", ctx.plaintext_len);

      	return 0;
}
