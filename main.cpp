#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "AES/aes.h"

int test_aes()
{
	uint8_t key[16] = { 0xEE ,0x14 ,0x5F ,0x6D ,0xCD ,0x6F ,0xE1 ,0x98 ,0x53 ,0x44 ,0xD4 ,0xBB ,0x65 ,0x5B ,0xC6 ,0xA3 };/*第一次加密密钥*/
	uint8_t input[16] = { 0 };
	uint8_t output[16] = { 0 };
	uint8_t dec[16] = { 0 };
	aes128_t* aes128;
	int i, cnt;

	aes128 = aes128_init(key);
	if (aes128 == NULL)
	{
		printf("AES 初始化失败\n");
		return 0;
	}

	srand(GetTickCount64());

	for (cnt = 0; cnt < 10000; cnt++)
	{
		for (i = 0; i < 16; i++)
		{
			input[i] = rand() & 0xFF;
		}

		aes128_enc(aes128, input, output);
		aes128_dec(aes128, output, dec);

		if (memcmp(dec, input, 16) != 0)
		{
			printf("AES 校验失败\n");
			return 0;
		}
	}
	aes128_free(aes128);

	return 1;
}

int main()
{
	test_aes();

	return 0;
}