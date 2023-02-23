/*    tawny.h    */

/*
 * Author: ripmeep
 * GitHub: https://github.com/ripmeep/
 * Date  : 24/03/2019
 */

/* TODO:
 *  - Seperate declarations and definitions into
 *    seperate files (tawny.h & tawny.c).
 *
 *  - Create macro functions for table shifting
 *    operations on rows & columns instead of
 *    manual shifting.
 *
 *  - Add an SBOX and RBOX to obfuscate ciphertext
 *    a bit more.
 *
 *  - Add a tawny_free(...) function to free context
 *    memory.
 *
 *  - Add a tawny_pkcs7unpad(...) function to unpad
 *    decrypted text with PKCS#7 padding.
 */

/*    INCLUDES    */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*    MACROS & PREPROCESSOR DEFINITIONS    */
#ifndef _TAWNY_H_

#define TAWNY_DEBUG         0
#define TAWNY_BLOCK_SIZE    32               /* 256 bit encryption algorithmi (32 * 8). */
#define TAWNY_KEY_SIZE      TAWNY_BLOCK_SIZE
#define TAWNY_IV_SIZE       TAWNY_BLOCK_SIZE /* Full block initialization
                                                vector. */

/*    TYPE DEFINITIONS    */
typedef enum
{
    TAWNY_UPDATE_IV,
    TAWNY_UPDATE_KEY,
    TAWNY_UPDATE_PLAINTEXT,
    TAWNY_UPDATE_CIPHERTEXT,
} tawny_update_t; /* This isn't needed, but could maybe
                     use it in the future for a global
                     update function such as the old version. */

struct __tawny_matrix /* Mangled as not used by user. */
{
    uint32_t    rows;
    uint32_t    cols;
    uint32_t    table[4][8];
};

typedef struct __tawny_ctx_t
{
    unsigned char*          plaintext;
    size_t                  plaintext_len;

    unsigned char*          ciphertext;
    size_t                  ciphertext_len;

    unsigned char           key[TAWNY_KEY_SIZE];
    unsigned char           iv[TAWNY_IV_SIZE];

    struct __tawny_matrix   tm;

    unsigned char           keyround[TAWNY_BLOCK_SIZE];
} tawny_ctx_t;

/*    FUNCTION DEFINITIONS    */
size_t tawny_pkcs7pad(unsigned char* buf, size_t len,
                      unsigned char** out, size_t block_size)
/* Padding function to keep plaintext length strict to block size.
 *
 * m = modulo((block size - length), block size)
 * plaintext += m * m
 *
 * Where m is the number of characters and the ASCII char to pad.
 */
{
    int             n;
    unsigned char*  pad;
    size_t          nlen;

    n = ((block_size - len) % block_size);
    n = (n == 0) ? block_size : n; /* If pad value is 0, set it to the
                                      block size instead. */

    nlen = len + n;
    pad = (unsigned char*)malloc(nlen);

    if (pad == NULL)
        return 0;

    memcpy(pad, buf, len);

    for (int i = 0; i < n; i++)
        pad[len + i] = (unsigned char)n;

    *out = (unsigned char*)malloc(nlen);

    if (out == NULL)
        return 0;

    memcpy(*out, pad, nlen);

    return nlen;
}

size_t t_xor(unsigned char* md, size_t md_len,
             unsigned char* buf1, size_t len1,
             unsigned char* buf2, size_t len2)
{
/* Not really meant to be used by the user, but can be a useful function
 * to extend.
 *
 * Length of XOR variables cannot be greater than the output buffer size.
 *
 * Ensures safety for XORing strings.
 */
    size_t sz, wz;

    sz = wz = 0;

    if (len1 > md_len || len2 > md_len) /* Ensure safety. */
        return 0;

    wz = (len1 > len2) ? len2 : len1;

    for (sz = 0; sz < wz; sz++)
         md[sz] = buf1[sz] ^ buf2[sz];

    return sz; /* Length of new buffer depending on len1 and len2. */
}

uint8_t tawny_update_iv(struct __tawny_ctx_t* ctx, unsigned char* iv, size_t len)
{
    if (len != TAWNY_IV_SIZE)
        return 0;

    memset(ctx->iv, 0, TAWNY_IV_SIZE);
    memcpy(ctx->iv, iv, TAWNY_IV_SIZE);

    return (!memcmp(ctx->iv, iv, TAWNY_KEY_SIZE)) ? 1 : 0; /* Copy ok? */
}

uint8_t tawny_update_key(struct __tawny_ctx_t* ctx, unsigned char* key, size_t len)
{
    if (len != TAWNY_KEY_SIZE)
        return 0;

    memset(ctx->key, 0, TAWNY_KEY_SIZE);
    memcpy(ctx->key, key, TAWNY_KEY_SIZE);

    return (!memcmp(ctx->key, key, TAWNY_KEY_SIZE)) ? 1 : 0; /* Copy ok? */
}

uint8_t tawny_update_plaintext(struct __tawny_ctx_t* ctx, unsigned char* plaintext, size_t len)
{
    if (len < TAWNY_BLOCK_SIZE)
        return 0;

    ctx->plaintext = (unsigned char*)malloc(len + 1);

    if (ctx->plaintext == NULL)
        return 0;

    memcpy(ctx->plaintext, plaintext, len);

    ctx->plaintext_len = len;

    return (!memcmp(ctx->plaintext, plaintext, len)) ? 1 : 0; /* Copy ok? */
}

uint8_t tawny_update_ciphertext(struct __tawny_ctx_t* ctx, unsigned char* ciphertext, size_t len)
{
    if (len < TAWNY_BLOCK_SIZE)
        return 0;

    ctx->ciphertext = (unsigned char*)malloc(len + 1);

    if (ctx->ciphertext == NULL)
        return 0;

    memcpy(ctx->ciphertext, ciphertext, len);

    ctx->ciphertext_len = len;

    return (!memcmp(ctx->ciphertext, ciphertext, len)) ? 1 : 0; /* Copy ok? */
}

size_t tawny_encrypt(struct __tawny_ctx_t* ctx)
{
    size_t          nmemb, total_len, pos;
    unsigned char   block[TAWNY_BLOCK_SIZE];
    int             val;

    if (ctx->plaintext_len == 0 || ctx->plaintext == NULL) /* Don't encrypt nothing. */
        return -1;

    for (size_t r = 0; r < ctx->tm.rows; r++) /* Empty the matrix table. */
    {
        for (size_t c = 0; c < ctx->tm.cols; c++)
            ctx->tm.table[r][c] = 022;
    }

    if (!t_xor(ctx->keyround,
               TAWNY_BLOCK_SIZE,
               ctx->key,
               TAWNY_KEY_SIZE,
               ctx->iv,
               TAWNY_IV_SIZE)) /* Initialize keyround. */
        return 0;

    nmemb = ctx->plaintext_len / TAWNY_BLOCK_SIZE;
    total_len = TAWNY_BLOCK_SIZE * nmemb; /* Total length of the ciphertext will be nmemb * block size. */
    pos = 0;

    ctx->ciphertext = (unsigned char*)malloc(total_len + 1);

    if (ctx->ciphertext == NULL)
        return 0;

    memset(ctx->ciphertext, 0, total_len + 1);

    ctx->ciphertext_len = 0;

    for (int e = 0; e < nmemb; e++)
    {
        memset(block, 0, TAWNY_BLOCK_SIZE);
        memcpy(block, ctx->plaintext + (TAWNY_BLOCK_SIZE * e), TAWNY_BLOCK_SIZE); /* Copy current
                                                                                     block of plaintext. */

        if (!t_xor(block,
                   TAWNY_BLOCK_SIZE,
                   ctx->keyround,
                   TAWNY_BLOCK_SIZE,
                   block,
                   TAWNY_BLOCK_SIZE))
            return 0;

        for (size_t r = 0; r < ctx->tm.rows; r++) /* Fill matrix with current keyround. */
        {
            for (size_t c = 0; c < ctx->tm.cols; c++)
            {
                pos = c + (r * ctx->tm.cols);

                ctx->tm.table[r][c] = (uint32_t)block[pos];
                ctx->keyround[pos] = block[pos];
            }
        }

        for (size_t c = 0; c < ctx->tm.cols; c++) /* Swap and shift columns. */
        {
            val = ctx->tm.table[0][c];

            ctx->tm.table[0][c] = ctx->tm.table[2][c];
            ctx->tm.table[2][c] = val;
        }

        for (size_t c = 0; c < ctx->tm.cols; c++) /* Swap and shift columns. */
        {
            val = ctx->tm.table[1][c];
            
            ctx->tm.table[1][c] = ctx->tm.table[3][c];
            ctx->tm.table[3][c] = val;
        }

        for (size_t r = 0; r < ctx->tm.rows; r++) /* Swap and shift rows (descending). */
        {
            val = ctx->tm.table[r][0];

            ctx->tm.table[r][0] = ctx->tm.table[r][7];
            ctx->tm.table[r][7] = val;

            val = ctx->tm.table[r][1];

            ctx->tm.table[r][1] = ctx->tm.table[r][6];
            ctx->tm.table[r][6] = val;

            val = ctx->tm.table[r][2];

            ctx->tm.table[r][2] = ctx->tm.table[r][5];
            ctx->tm.table[r][5] = val;

            val = ctx->tm.table[r][3];
            
            ctx->tm.table[r][3] = ctx->tm.table[r][4];
            ctx->tm.table[r][4] = val;
        }


        for (size_t r = 0; r < ctx->tm.rows; r++) /* Unload each row of matrix values into ciphertext. */
        {
            for (size_t c = 0; c < ctx->tm.cols; c++)
            {
                pos = c + (r * ctx->tm.cols);

                ctx->ciphertext[(TAWNY_BLOCK_SIZE * e) + pos] = (unsigned char)ctx->tm.table[r][c] & 0xFF;
                ctx->ciphertext_len++;
            }
        }
    }

    ctx->ciphertext[ctx->ciphertext_len] = '\0';

    return ctx->ciphertext_len;
}

size_t tawny_decrypt(struct __tawny_ctx_t* ctx)
{
    size_t          nmemb, total_len, pos;
    unsigned char   block[TAWNY_BLOCK_SIZE];
    int             val;

    if (ctx->ciphertext_len == 0 || ctx->ciphertext == NULL)
        return 0;

    if (!t_xor(ctx->keyround,
               TAWNY_BLOCK_SIZE,
               ctx->key,
               TAWNY_KEY_SIZE,
               ctx->iv,
               TAWNY_IV_SIZE)) /* Initialize keyround. */
        return 0;

    for (size_t r = 0; r < ctx->tm.rows; r++) /* Empty matrix table. */
    {
        for (size_t c = 0; c < ctx->tm.cols; c++)
            ctx->tm.table[r][c] = 022;
    }

    nmemb = ctx->ciphertext_len / TAWNY_BLOCK_SIZE;
    total_len = TAWNY_BLOCK_SIZE * nmemb;
    pos = 0;

    ctx->plaintext = (unsigned char*)malloc(total_len + 1);

    if (ctx->plaintext == NULL)
        return 0;

    memset(ctx->plaintext, 0, total_len + 1);

    ctx->plaintext_len = 0;

    for (int d = 0; d < nmemb; d++)
    {
        memset(block, 0, TAWNY_BLOCK_SIZE);
        memcpy(block, ctx->ciphertext + (TAWNY_BLOCK_SIZE * d), TAWNY_BLOCK_SIZE); /* Copy current
                                                                                      block of ciphertext. */

        for (size_t r = 0; r < ctx->tm.rows; r++) /* Load matrix table with current ciphertext bytes. */
        {
            for (size_t c = 0; c < ctx->tm.cols; c++)
            {
                pos = c + (r * ctx->tm.cols);

                ctx->tm.table[r][c] = (uint32_t)block[pos];
            }
        }

        for (size_t c = 0; c < ctx->tm.cols; c++) /* Shift (unshift) columns. */
        {
            val = ctx->tm.table[2][c];

            ctx->tm.table[2][c] = ctx->tm.table[0][c];
            ctx->tm.table[0][c] = val;
        }

        for (size_t c = 0; c < ctx->tm.cols; c++) /* Shift (unshift) columns. */
        {
            val = ctx->tm.table[3][c];

            ctx->tm.table[3][c] = ctx->tm.table[1][c];
            ctx->tm.table[1][c] = val;
        }

        for (size_t r = 0; r < ctx->tm.rows; r++) /* Shift (unshift) rows (descending). */
        {
            val = ctx->tm.table[r][7];

            ctx->tm.table[r][7] = ctx->tm.table[r][0];
            ctx->tm.table[r][0] = val;

            val = ctx->tm.table[r][6];

            ctx->tm.table[r][6] = ctx->tm.table[r][1];
            ctx->tm.table[r][1] = val;

            val = ctx->tm.table[r][5];
            
            ctx->tm.table[r][5] = ctx->tm.table[r][2];
            ctx->tm.table[r][2] = val;

            val = ctx->tm.table[r][4];

            ctx->tm.table[r][4] = ctx->tm.table[r][3];
            ctx->tm.table[r][3] = val;
        }

        for (size_t r = 0; r < ctx->tm.rows; r++) /* Unload unshifted matrix values into current plaintext block. */
        {
            for (size_t c = 0; c < ctx->tm.cols; c++)
            {
                pos = c + (r * ctx->tm.cols);

                block[pos] = (unsigned char)ctx->tm.table[r][c] & 0xFF;
            }
        }

        if (!t_xor(block,
                   TAWNY_BLOCK_SIZE,
                   ctx->keyround,
                   TAWNY_BLOCK_SIZE,
                   block,
                   TAWNY_BLOCK_SIZE)) /* Decrypt (XOR). */
            return 0;

        for (size_t i = 0; i < TAWNY_BLOCK_SIZE; i++)
        {
            ctx->plaintext[i + (TAWNY_BLOCK_SIZE * d)] = block[i]; /* Unlock current block to plaintext buffer. */
            ctx->plaintext_len++;
        }

        if (!t_xor(ctx->keyround,
                   TAWNY_BLOCK_SIZE,
                   ctx->keyround,
                   TAWNY_BLOCK_SIZE,
                   block,
                   TAWNY_BLOCK_SIZE))
            return 0;
    }

    return ctx->plaintext_len;
}

struct __tawny_ctx_t* tawny_init(unsigned char* key, size_t key_len,
								 unsigned char* iv, size_t iv_len)
{
    struct __tawny_ctx_t*   ctx;

    ctx = (struct __tawny_ctx_t*)malloc( sizeof(struct __tawny_ctx_t) );

    if (ctx == NULL)
        return NULL;

    ctx->plaintext_len = 0;
    ctx->plaintext = NULL;

    ctx->ciphertext_len = 0;
    ctx->ciphertext = NULL;

    ctx->tm.rows = 4;
    ctx->tm.cols = 8;

    memset(ctx->key, 0, TAWNY_KEY_SIZE);
    memset(ctx->iv, 0, TAWNY_IV_SIZE);

    if (key != NULL)
    {
	    if (!tawny_update_key(ctx, key, key_len))
		    return NULL;
    }

    if (iv != NULL)
    {
	    if (!tawny_update_iv(ctx, iv, iv_len))
		    return NULL;
    }

    return ctx;
}

#define _TAWNY_H_
#endif
