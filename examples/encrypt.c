#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#include "tawny.h"

int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "\nUsage: [PLAINTEXT FILE] [KEY FILE] [OUTPUT FILE]\n\n");
		return -1;
	}

	char * plaintext_filename = argv[1];
	char * key_filename = argv[2];
	char * out_filename = argv[3];

	FILE * plaintext_file = fopen(plaintext_filename, "r");
	FILE * key_file = fopen(key_filename, "rb");

	if (plaintext_file == NULL || key_file == NULL) {
		fprintf(stderr, "Failed to open file \"%s\" [fopen()]\n", (plaintext_file == NULL)?argv[1]:argv[2]);
		perror("Error");
		return -1;
	}

	long plaintext_len, key_len = 0;

	fseek(plaintext_file, 0, SEEK_END); 	/* GO TO END OF PLAINTEXT FILE */
	fseek(key_file, 0, SEEK_END); 		/* GET FIRST 32 BYTES OF KEY */

	plaintext_len = ftell(plaintext_file);	/* STORE LENGTH OF PLAINTEXT FILE */
	key_len = ftell(key_file);		/* STORE LENGTH OF ENCRYPTION KEY - 2 FOR LINE ENDING */

	rewind(plaintext_file);	/* RESET POSITION OF FILES TO THE START */
	rewind(key_file);

	if (key_len != TAWNY_BLOCK_SIZE_BYTES) { 	/* CHECK LENGTH OF KEY */
		fprintf(stderr, "Key length incorrect (%ld)\nKey size must be 256 bits (32 bytes)\n", key_len);
		return -1;
	}

	char plaintext[plaintext_len];
	char key[TAWNY_BLOCK_SIZE_BYTES];
	char iv[TAWNY_BLOCK_SIZE_BYTES];	/* INITIALIZATION VECTOR MUST BE SAME SIZE AS BLOCK SIZE (256 BITS) */

	if (!RAND_bytes(iv, sizeof(iv))) {
		fprintf(stderr, "Failed to randomly generate IV [RAND_bytes()] (NOT CRITICAL BUT UNSAFE)\nAborting...");
		return -1;
	}

	fread(plaintext, 1, plaintext_len, plaintext_file);
	fread(key, 1, sizeof(key), key_file);

	plaintext[plaintext_len] = '\0';	/* ZERO OUT THE fread() */

	/* PAD THE PLAINTEXT TO THE REQUIRED BLOCK SIZE DIVISION */
	char * padded_plaintext = pkcs7pad(plaintext, strlen(plaintext), TAWNY_BLOCK_SIZE_BYTES);

	Tawny_CTX ctx;
	Tawny_Init(&ctx);

	/* int Tawny_Update(int mode, Tawny_CTX * ctx, unsigned char * iv, unsigned char * key, unsigned char * plaintext, unsigned char * ciphertext, size_t plaintext_len, size_t ciphertext_len); */

	if (!Tawny_Update(TAWNY_UPDATE_PLAINTEXT, &ctx, NULL, NULL, padded_plaintext, NULL, strlen(padded_plaintext), 0)) {
		fprintf(stderr, "Tawny_Update() failed to update the plaintext\nAborting...\n");
		return -1;
	}

	if (!Tawny_Update(TAWNY_UPDATE_KEY, &ctx, NULL, key, NULL, NULL, 0, 0)) {
		fprintf(stderr, "Tawny_Update() failed to update the encryption key\nAborting...\n");
		return -1;
	}

	if (!Tawny_Update(TAWNY_UPDATE_IV, &ctx, iv, NULL, NULL, NULL, 0, 0)) {
		fprintf(stderr, "Tawny_Update() failed to update the IV\nAborting...\n");
		return -1;
	}

	size_t bytes_written = 0;

	/* Tawny_Encrypt() RETURNS THE AMOUNT OF COPIED BYTES ON SUCCESS AND 0 ON FAILURE */

	bytes_written = Tawny_Encrypt(&ctx);

	if (bytes_written < 1) {
		fprintf(stderr, "Tawny_Encrypt() failed.\nAborting...\n");
		return -1;
	}

	/* ENCRYPTED TEXT/CIPHERTEXT IS NOW STORED IN ctx.ciphertext */
	/* LENGTH OF CIPHERTEXT IS STORED IN ctx.ciphertext_len */

	FILE * outfile = fopen(out_filename, "wb");

	if (outfile == NULL) {
		fprintf(stderr, "Failed to open file file for writing \"%s\" [fopen()]\n", (outfile == NULL)?argv[1]:argv[2]);
		perror("Error");
		return -1;
	}

	/* WRITE CIPHERTEXT TO NEW FILE */

	fwrite(ctx.ciphertext, ctx.ciphertext_len, 1, outfile);
	fwrite(iv, TAWNY_BLOCK_SIZE_BYTES, 1, outfile);

	printf("Success!\nEncrypted data now stored in \"%s\"\n", out_filename);

	return 0;
}
