/*
  @Date: 2018/12/9
  @Version: 1.0.0
  @Author: MJS
  @Description: SHA1 arithmetic head file
  				input:  <=2^64bit(512bit pre package)
				output: 160bit(SHA1 value)
*/

#ifndef __SHA1_H__
#define __SHA1_H__

#include<stdlib.h>
#include<stdint.h>
#include<string.h>

/* define function pre sub_block*/
#define F0(X,Y,Z) (Z^(X&(Y^Z)))		//i:[00,19]
#define F1(X,Y,Z) (X^Y^Z)			//i:[20,39]
#define F2(X,Y,Z) ((X&Y)|(Z&(X|Y)))	//i:[40,59]
#define F3(X,Y,Z) (X^Y^Z)			//i:[60,79]
#define Sn(X,n) ((X<<n)|(X>>(32-n)))
#define ByteToInt(X) ((*((uint8_t*)X)<<24)|(*((uint8_t*)X+1)<<16)|(*((uint8_t*)X+2)<<8)|(*((uint8_t*)X+3)))

/* define struct of SHA1*/
struct SHA1_t
{
	/* 5 variable */
	uint32_t H0;
	uint32_t H1;
	uint32_t H2;
	uint32_t H3;
	uint32_t H4;
	
	/* SHA1 data, must be 512bits(16block,32bit pre sub_block) */
	uint8_t data[64];
	
	/* SHA1 extend data */
	uint32_t edata[80];
};

/* define function declaration*/
uint8_t SHA1(uint8_t *sha1, uint8_t *input, int size);
void SHA1_init(struct SHA1_t *SHA1t);
void SHA1_sub(struct SHA1_t *SHA1t);
void SHA1_extend(struct SHA1_t *SHA1t);
#endif

