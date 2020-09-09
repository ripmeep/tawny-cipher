#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#include "tawny.h"

int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "\nUsage: [CIPHERTEXT FILE] [KEY FILE] [OUT FILE]\n\n");
		return -1;
	}

	char * ciphertext_filename = argv[1];
	char * key_filename = argv[2];
	char * out_filename = argv[3];

	FILE * ciphertext_file = fopen(ciphertext_filename, "rb");
	FILE * key_file = fopen(key_filename, "rb");

	if (ciphertext_file == NULL || key_file == NULL) {
		fprintf(stderr, "Failed to open file \"%s\" [fopen()]\n", (ciphertext_file == NULL)?argv[1]:argv[2]);
		perror("Error");
		return -1;
	}

	long ciphertext_len, key_len = 0;

	fseek(ciphertext_file, 0, SEEK_END); 	/* GO TO END OF CIPHERTEXT FILE */
	fseek(key_file, 0, SEEK_END); 		/* GET FIRST 32 BYTES OF KEY */

	ciphertext_len = ftell(ciphertext_file);	/* STORE LENGTH OF CIPHERTEXT FILE - LENGTH OF IV AT END */
	key_len = ftell(key_file);			/* STORE LENGTH OF ENCRYPTION KEY - 2 FOR LINE ENDING */

	rewind(ciphertext_file);	/* RESET POSITION OF FILES TO THE START */
	rewind(key_file);

	if (key_len != TAWNY_BLOCK_SIZE_BYTES) { 	/* CHECK LENGTH OF KEY */
		fprintf(stderr, "Key length incorrect (%ld)\nKey size must be 256 bits (32 bytes)\n", key_len);
		return -1;
	}

	ciphertext_len = ciphertext_len - TAWNY_BLOCK_SIZE_BYTES;

	char ciphertext[ciphertext_len];
	char key[TAWNY_BLOCK_SIZE_BYTES];
	char iv[TAWNY_BLOCK_SIZE_BYTES];	/* INITIALIZATION VECTOR MUST BE SAME SIZE AS BLOCK SIZE (256 BITS) */

	fread(ciphertext, 1, ciphertext_len, ciphertext_file); /* READ CIPHERTEXT EXCEPT IV */
	fread(key, 1, sizeof(key), key_file);

	rewind(ciphertext_file);
	fseek(ciphertext_file, ciphertext_len, SEEK_SET);

	fread(iv, 1, sizeof(iv), ciphertext_file);

	ciphertext[ciphertext_len]  = '\0'; /* ZERO OUT THE fread() TO THE END OF THE CIPHERTEXT */

	Tawny_CTX ctx;
	Tawny_Init(&ctx);

	/* int Tawny_Update(int mode, Tawny_CTX * ctx, unsigned char * iv, unsigned char * key, unsigned char * plaintext, unsigned char * ciphertext, size_t plaintext_len, size_t ciphertext_len); */

	if (!Tawny_Update(TAWNY_UPDATE_CIPHERTEXT, &ctx, NULL, NULL, NULL, ciphertext, 0, ciphertext_len)) {
		fprintf(stderr, "Tawny_Update() failed to update the ciphertext\nAborting...\n");
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

	/* Tawny_Decrypt RETURNS THE AMOUNT OF COPIED BYTES ON SUCCESS AND 0 ON FAILURE */

	bytes_written = Tawny_Decrypt(&ctx);

	if (bytes_written < 1) {
		fprintf(stderr, "Tawny_Decrypt() failed.\nAborting...\n");
		return -1;
	}

	/* PLAINTEXT IS NOW STORED IN ctx.plaintext */
	/* LENGTH OF PLAINTEXT IS STORED IN ctx.plaintext_len */

	FILE * outfile = fopen(out_filename, "wb");

	if (outfile == NULL) {
		fprintf(stderr, "Failed to open file file for writing \"%s\" [fopen()]\n", (outfile == NULL)?argv[1]:argv[2]);
		perror("Error");
		return -1;
	}

	/* WRITE PLAINTEXT TO NEW FILE */

	fwrite(ctx.plaintext, ctx.plaintext_len, 1, outfile);

	printf("Success!\nDecrypted data now stored in \"%s\"\n", out_filename);
	printf("Data: %s\n", ctx.plaintext);

	return 0;
}
