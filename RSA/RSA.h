/*
  @Date: 2018/12/10
  @Version: 1.0.2
  @Author: MJS
  @Description:
	RSA decoder head file
	big number(bn) data foramt for operation is little end and dword
	example:
		bn->bnd = {0xD6413FD1,0x0214BEFF,0x7505FB56,0x09127C47};
		bn->size = 4;
		the actual bn is 0x9127C477505FB560214BEFFD6413FD1
	RSA_t data format is big end
	example:
		input[] = {0x30,0x31,0x32,0x33,0x34,0x35};
		len = 6;
		the actual bn is 0x303132333435
  @history:
	1.0.1: Fix some bugs
	2022/1/11 - v1.0.2: add something
*/
#ifndef ALGORITHM_RSA_H_
#define ALGORITHM_RSA_H_

#include<stdlib.h>
#include<stdint.h>
#include<string.h>

struct RSA_t
{
	uint8_t* cipherText; /* encrypt data*/
	int CTsize;

	uint8_t* n;
	int Nsize;

	uint8_t* key;
	int Ksize;

	uint8_t* plainText; /* decrypt data*/
	int PTsize;    /*must more than Nsize*/
};

struct bn_t
{
	uint32_t* bnd;   /*big number data, reverse order*/
	int  size;  /*how many dword of bn*/
};

int RSA(struct RSA_t* RSAt);
int RSA_enc(void* cipher, int cipher_len, void* plain, int plain_len, char* key, char* n);
int RSA_dec(void* cipher, int cipher_len, void* plain, int plain_len, char* e, char* n);

int bmul(struct bn_t* src_dst, struct bn_t* src);
int bmod(struct bn_t* src_dst, struct bn_t* src);
struct bn_t* badd(struct bn_t* src1, struct bn_t* src2);

struct bn_t* binit(uint8_t* bnSeq, uint32_t size);
int bfree(struct bn_t* bn);
void print_bn(struct bn_t* bn);

uint8_t* rsa_byte_init(char* hex);
int rsa_byte_len(char* hex);
void rsa_byte_free(uint8_t* byte);

#endif	//ALGORITHM_RSA_H_
