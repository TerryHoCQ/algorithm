/*
  @Date: 2018/12/10
  @Version: 1.0.1
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
*/
#ifndef HEAD_RSA
#define HEAD_RSA

#include<stdlib.h>
#include<stdint.h>
#include<string.h>

#define HIDWORD(X) (*((uint32_t*)&(X)+1))
#define LODWORD(X) (*((uint32_t*)&(X)))
#define ByteToInt(X) ((*((uint8_t*)X)<<24)|(*((uint8_t*)X+1)<<16)|(*((uint8_t*)X+2)<<8)|(*((uint8_t*)X+3)))
#define ResInt(X)  ((4-(X&0x3))&0x3)  //ex: X=35, 35*4=8бнбн3  return (4-3) 
#define CeilInt(X) ((X+3)&0xFFFFFFFC) //ex: X=78, 78*4=19бнбн2  return (19+1)
#define MakeQword(X,Y) ((((uint64_t)(X))<<32)|(Y))

struct RSA_t
{
	uint8_t* cipherText; /* encrypt data*/
	uint32_t CTsize;

	uint8_t* n;
	uint32_t Nsize;

	uint8_t* key;
	uint32_t Ksize;

	uint8_t* plainText; /* decrypt data*/
	uint32_t PTsize;    /*must more than Nsize*/
};

struct bn_t
{
	uint32_t* bnd;   /*big number data, reverse order*/
	uint32_t  size;  /*how many dword of bn*/
};

uint8_t        RSA(struct RSA_t* RSAt);

uint8_t        bmul(struct bn_t* a, struct bn_t* b);
uint8_t        bmod(struct bn_t* a, struct bn_t* b);
struct bn_t* badd(struct bn_t* a, struct bn_t* b);

struct bn_t* binit(uint8_t* bnSeq, uint32_t size);
uint8_t        bdeit(struct bn_t* bnt);
uint32_t       bseq(uint8_t* seq, struct bn_t* bnt);
void           bcpy(struct bn_t* a, struct bn_t* b);

uint8_t        byteReverse(uint8_t* a, uint16_t length);
uint32_t* formatByte(uint8_t* a, uint32_t* len);
void           print_bn(struct bn_t* bn);

#endif
