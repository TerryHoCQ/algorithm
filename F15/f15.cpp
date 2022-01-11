#include "aes.h"
#include "f15.h"
#include <stdlib.h>
#include <string.h>

#ifndef nullptr
#define nullptr NULL
#endif

/* 协议R1-R5默认值：64 0 32 64 96 */
/* 运营商自定义值：32 19 47 73 91 */
static uint8_t g_KI[16] = {0};
static uint8_t g_OPC[16] = {0};
static uint8_t g_R1 = 64;
static uint8_t g_R2 = 0;
static uint8_t g_R3 = 32;
static uint8_t g_R4 = 64;
static uint8_t g_R5 = 96; 
static uint8_t g_C1[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t g_C2[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
static uint8_t g_C3[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
static uint8_t g_C4[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04};
static uint8_t g_C5[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08};

static void rol(uint8_t *in, uint8_t bits)
{
	int i;
	uint8_t temp;
	static uint8_t mask[9] = {0x00,0x80,0xC0,0xE0,0xF0,0xF8,0xFC,0xFE,0xFF};

	/* rol 8bits first */
	while(bits >= 8)
	{
		temp = in[0];
		for(i=0;i<15;i++)
			in[i] = in[i+1];
		in[15] = temp;
		bits -= 8;
	}

	/* rol xbits */
	if(bits > 0)
	{
		temp = in[0]&mask[bits];
		for(i=0;i<15;i++)
			in[i] = (in[i] << bits) | ((in[i+1] & mask[bits]) >> (8-bits));
		in[15] = (in[15] << bits) | (temp >> (8-bits));
	}
}

void setKPC(uint8_t *ki, uint8_t *opc)
{
	memcpy(g_KI,ki,16);
	memcpy(g_OPC,opc,16);
}

void setRC(int n, uint8_t *c, uint8_t r)
{
	switch(n)
	{
		case 1:
			g_R1 = r;
			if(c)
				memcpy(g_C1,c,16);
		case 2:
			g_R2 = r;
			if(c)
				memcpy(g_C2,c,16);
		case 3:
			g_R3 = r;
			if(c)
				memcpy(g_C3,c,16);
		case 4:
			g_R4 = r;
			if(c)
				memcpy(g_C4,c,16);
		case 5:
			g_R5 = r;
			if(c)
				memcpy(g_C5,c,16);
	}
}

static void f1_s(uint8_t *rand, uint8_t *input, uint8_t *MAC_A, uint8_t *MAC_S)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);
	
	for (i = 0; i<16; i++)
		rijndaelInput[i] = input[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R1);
	
	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C1[i];

	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= temp[i];
		
	aes128_enc(aes, rijndaelInput, out);
	
	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	if(MAC_A)
	{
		for (i = 0; i<8; i++)
			MAC_A[i] = out[i];
	}

	if(MAC_S)
	{
		for (i = 0; i<8; i++)
			MAC_S[i] = out[i+8];
	}

	aes128_free(aes);
}

void f1(uint8_t *rand, uint8_t *input, uint8_t *MAC_A)
{
	f1_s(rand, input, MAC_A, nullptr);
}

void f1start(uint8_t *rand, uint8_t *input, uint8_t *MAC_S)
{
	f1_s(rand, input, nullptr, MAC_S);
}

void f2(uint8_t *rand, uint8_t *RES)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);


	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R2);
	
	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C2[i];

	aes128_enc(aes, rijndaelInput, out);

	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	for (i = 0; i<8; i++)
		RES[i] = out[i+8];

	aes128_free(aes);
}

void f3(uint8_t *rand, uint8_t *CK)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R3);

	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C3[i];

	aes128_enc(aes, rijndaelInput, out);

	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	for (i = 0; i<16; i++)
		CK[i] = out[i];

	aes128_free(aes);
}

void f4(uint8_t *rand, uint8_t *IK)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);


	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R4);

	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C4[i];

	aes128_enc(aes, rijndaelInput, out);

	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	for (i = 0; i<16; i++)
		IK[i] = out[i];

	aes128_free(aes);
}

void f5(uint8_t *rand, uint8_t *AK)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);


	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R2);

	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C2[i];

	aes128_enc(aes, rijndaelInput, out);

	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	for (i = 0; i<6; i++)
		AK[i] = out[i];

	aes128_free(aes);
}

void f5star(uint8_t *rand, uint8_t *AK)
{
	uint8_t temp[16] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t rijndaelInput[16] = { 0 };
	int i;
	aes128_t* aes = nullptr;

	aes = aes128_init(g_KI);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ g_OPC[i];
	aes128_enc(aes, rijndaelInput, temp);


	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ g_OPC[i];

	rol(rijndaelInput, g_R5);

	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= g_C5[i];

	aes128_enc(aes, rijndaelInput, out);

	for (i = 0; i<16; i++)
		out[i] ^= g_OPC[i];

	for (i = 0; i<6; i++)
		AK[i] = out[i];

	aes128_free(aes);
}
