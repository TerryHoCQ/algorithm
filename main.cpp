#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#include "SHA1/SHA1.h"
#include "AES/aes.h"
#include "F15/f15.h"
#include "RSA/RSA.h"

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

	srand(GetTickCount());

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

int test_f15()
{
	int flag = 1;
	uint8_t KI[] = { 0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc };
	uint8_t RAND[] = { 0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35 };
	uint8_t OPC[] = { 0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf };
	uint8_t SRES[] = { 0x46, 0xf8, 0x41, 0x6a, 0xa5, 0x42, 0x11, 0xd5 };
	uint8_t CK[] = { 0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05, 0xbb, 0xf0, 0xd9, 0x87, 0xb2, 0x1b, 0xf8, 0xcb };
	uint8_t IK[] = { 0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04, 0x12, 0x76, 0x72, 0x71, 0x1c, 0x6d, 0x34, 0x41 };
	uint8_t xck[16], xik[16], xres[8];

	f2(RAND, xres);
	f3(RAND, xck);
	f3(RAND, xik);

	if (memcmp(xres, SRES, 8) != 0)
	{
		printf("f2 check failed\n");
		flag = 0;
	}
	else
	{
		printf("f2 check ok\n");
	}

	if (memcmp(xck, CK, 16) != 0)
	{
		printf("f3 check failed\n");
		flag = 0;
	}
	else
	{
		printf("f3 check ok\n");
	}

	if (memcmp(xik, IK, 16) != 0)
	{
		printf("f4 check failed\n");
		flag = 0;
	}
	else
	{
		printf("f4 check ok\n");
	}

	return flag;
}

int test_sha1()
{
	char input[] = "this is a sha1 input";
	uint8_t sha1_v[20] = { 0 };
	uint8_t xsha1_v[20] = { 0xFC, 0xA1, 0xA7, 0x5A, 0x95, 0x98, 0xAD, 0x0E, 0xCE, 0x1A, 0x04, 0x78, 0x25, 0xE1, 0xF2, 0xA3, 0x8D, 0x63, 0xB1, 0x3F, };
	int i;


	SHA1(sha1_v, (uint8_t*)input, strlen(input));
	for (i = 0; i < 20; i++)
	{
		printf("%02X ", sha1_v[i]);
	}
	printf("\n");

	if(memcmp(sha1_v, xsha1_v, 20) != 0)
	{
		printf("sha1 check failed\n");
		return 0;
	}
	else
	{
		printf("sha1 check ok\n");
		return 1;
	}
}

uint8_t* first_nzero(uint8_t* data)
{
	while (*data == 0) { data++; }
	return data;
}

int test_rsa()
{
	int i, j;
	uint8_t plain[8] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37 };
	uint8_t cipher[32] = { 0x08,0xF2,0x32,0xD5,0xD0,0xA9,0x5E,0xFC,0x1F,0x00,0x77,0x22,0x2B,0xD5,0x4B,0x24,0x1D,0xED,0x29,0x9B,0x48,0xDB,0x05,0x80,0x2D,0xFC,0x10,0xBC,0x6A,0xC3,0x1E,0xD8 };
	uint8_t cipher2[32] = { 0 };
	uint8_t plain2[32] = { 0 };
	RSA_enc(cipher2, sizeof(cipher2), plain, sizeof(plain), "3FB9954DF90FE05207F2C044F0F5C34A45DCE3066018DEF4EADE48F2C48ADD31", "5D65A2EE78DAB424988ABADCE6B5FD072676BF7DE79016028DBDECA143785439");
	RSA_dec(cipher2, sizeof(cipher2), plain2, sizeof(plain2), "10001", "5D65A2EE78DAB424988ABADCE6B5FD072676BF7DE79016028DBDECA143785439");
	if (memcmp(cipher, first_nzero(cipher2), sizeof(cipher)) != 0 || memcmp(plain, first_nzero(plain2), sizeof(plain)) != 0)
	{
		printf("RSA 校验失败\n");
		for (j = 0; j < sizeof(cipher); j++)
		{
			printf("%02X ", (uint8_t)cipher[j]);
		}
		printf("\n");
		for (j = 0; j < sizeof(cipher2); j++)
		{
			printf("%02X ", (uint8_t)cipher2[j]);
		}
		printf("\n");
		for (j = 0; j < sizeof(plain); j++)
		{
			printf("%02X ", (uint8_t)plain[j]);
		}
		printf("\n");
		for (j = 0; j < sizeof(plain2); j++)
		{
			printf("%02X ", (uint8_t)plain2[j]);
		}
		return 0;
	}

	srand(GetTickCount());
	for (i = 0; i < 10000; i++)
	{
		for (j = 0; j < sizeof(plain); j++)
		{
			plain[j] = (uint8_t)rand();
		}
		if (plain[0] == 0)
		{
			plain[0]++;
		}

		RSA_enc(cipher, sizeof(cipher), plain, sizeof(plain), "3FB9954DF90FE05207F2C044F0F5C34A45DCE3066018DEF4EADE48F2C48ADD31", "5D65A2EE78DAB424988ABADCE6B5FD072676BF7DE79016028DBDECA143785439");
		RSA_dec(cipher, sizeof(cipher), plain2, sizeof(plain2), "10001", "5D65A2EE78DAB424988ABADCE6B5FD072676BF7DE79016028DBDECA143785439");

		if (memcmp(plain, first_nzero(plain2), sizeof(plain)) != 0)
		{
			printf("RSA 校验失败,i=%d\n",i);
			printf("plain: ");
			for (j = 0; j < sizeof(plain); j++)
			{
				printf("%02X", (uint8_t)plain[j]);
			}
			printf("\n");
			printf("cipher: ");
			for (j = 0; j < sizeof(cipher); j++)
			{
				printf("%02X", (uint8_t)cipher[j]);
			}
			printf("\n");
			printf("plain2: ");
			for (j = 0; j < plain2 + sizeof(plain2) - first_nzero(plain2); j++)
			{
				printf("%02X", (uint8_t)(first_nzero(plain2)[j]));
			}
			printf("\n");
			return 0;
		}
	}
	printf("RSA 校验成功\n");
	return 1;
}

int main()
{
	//test_aes();
	//test_f15();
	//test_sha1();
	test_rsa();
	return 0;
}