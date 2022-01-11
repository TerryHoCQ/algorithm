#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

typedef struct aes128_t
{
	uint8_t key[16];
	uint8_t roundkey[11][4][4];
} aes128_t;

aes128_t* aes128_init(uint8_t* key);
int aes128_dec(aes128_t* aes128, uint8_t* input, uint8_t* output);
int aes128_enc(aes128_t* aes128, uint8_t* input, uint8_t* output);
void aes128_free(aes128_t* aes128);

#endif
