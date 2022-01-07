/*
  @Date: 2018/12/9
  @Version: 1.0.0
  @Author: MJS
  @Description: SHA1 arithmetic
  				input:  <=2^64bit(512bit pre package)
				output: 160bit(SHA1 value)
*/

#include "SHA1.h"
#include<stdio.h>
#include<assert.h>

/* the first bit is 1, the rest bits are 0*/
const uint8_t padding[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
  @Fuction: SHA1
  @Param: uint8_t* sha1: output, 160bit, calculated sha1 value
  		  uint8_t* input: will be SHA1 data, must have 20byte
		  uint64_t size: assign how many byte of input
  @Return: uint8_t, success is 1,other is 0 
  @Description: calculate SHA1 value from input assigned size
*/
uint8_t SHA1(uint8_t *sha1, uint8_t *input, uint64_t size)
{
	struct SHA1_t SHA1t;
	uint8_t *data, padNum;
	uint64_t blockNum,i;
	
	if(input && sha1 && size>0)
	{
		SHA1_init(&SHA1t);
		
		padNum = size%64;
		blockNum = size/64;
		if(padNum != 0)
		{
			if(padNum <= 56)
			{
				data = malloc(size+64-padNum);
				memcpy(data,input,size);
				memcpy(data+size,padding,56-padNum);
				data[size+56-padNum] = (size*8)>>56;
				data[size+57-padNum] = (size*8)>>48;
				data[size+58-padNum] = (size*8)>>40;
				data[size+59-padNum] = (size*8)>>32;
				data[size+60-padNum] = (size*8)>>24;
				data[size+61-padNum] = (size*8)>>16;
				data[size+62-padNum] = (size*8)>>8;
				data[size+63-padNum] = (size*8);
				blockNum++;
			}else{
				data = malloc(size+128-padNum);
				memcpy(data,input,size); 
				memcpy(data+size,padding,120-padNum);
				data[size+120-padNum] = (size*8)>>56;
				data[size+121-padNum] = (size*8)>>48;
				data[size+122-padNum] = (size*8)>>40;
				data[size+123-padNum] = (size*8)>>32;
				data[size+124-padNum] = (size*8)>>24;
				data[size+125-padNum] = (size*8)>>16;
				data[size+126-padNum] = (size*8)>>8;
				data[size+127-padNum] = (size*8);
				blockNum+=2;
			}
		}else{
			data = malloc(size);
			memcpy(data,input,size);
		}
		
//		printf("data size:%d\nblock size:%d\n",size,blockNum);
		
		for(i=0;i<blockNum;i++)
		{
			memcpy(SHA1t.data,data+i*64,64);
			SHA1_sub(&SHA1t);
		}
					
		free(data);
		
		for (i = 0; i < 4; i++)
			sha1[i] = SHA1t.H0 >> (24 - i * 8);
		for (i = 0; i < 4; i++)
			sha1[4 + i] = SHA1t.H1 >> (24 - i * 8);
		for (i = 0; i < 4; i++)
			sha1[8 + i] = SHA1t.H2 >> (24 - i * 8);
		for (i = 0; i < 4; i++)
			sha1[12 + i] = SHA1t.H3 >> (24 - i * 8);
		for (i = 0; i < 4; i++)
			sha1[16 + i] = SHA1t.H4 >> (24 - i * 8);
		return 1;
	}
	return 0;
}

/*
  @Fuction: SHA1_init
  @Param: struct SHA1_t *SHA1_t: some information about SHA1
  @Return: void 
  @Description: init SHA1 parameter, must be call before SHA1_sub
*/
void SHA1_init(struct SHA1_t *SHA1t)
{
	if(SHA1t)
	{
		SHA1t->H0 = 0x67452301;
		SHA1t->H1 = 0xEFCDAB89;
		SHA1t->H2 = 0x98BADCFE;
		SHA1t->H3 = 0x10325476;
		SHA1t->H4 = 0xC3D2E1F0;
	}
}

/*
  @Fuction: SHA1_sub
  @Param: struct SHA1_t *SHA1t: some information about SHA1
  @Return: void 
  @Description: calculate SHA1 of the data with 512bit(must be 512bit)
*/
void SHA1_sub(struct SHA1_t *SHA1t)
{
	uint32_t i,A,B,C,D,E;
	uint64_t temp;

	if(SHA1t)
	{		
		SHA1_extend(SHA1t);
		
//		for(i=0;i<80;i++)
//		{
//			printf("%.8X",SHA1t->edata[i]);
//			i%4==3||i==79?printf("\n"):printf(" ");			
//		}
//		printf("\n");

		/* a copy */	
		A = SHA1t->H0;
		B = SHA1t->H1;
		C = SHA1t->H2;
		D = SHA1t->H3;
		E = SHA1t->H4;	
					
		for(i=0;i<20;i++)
		{	
			temp = Sn(A,5) + F0(B,C,D) + E + SHA1t->edata[i] + (uint32_t)0x5A827999;	
			E = D;
			D = C;
			C = Sn(B,30);
			B = A;
			A = temp;
		}
		
		for(;i<40;i++)
		{
			temp = Sn(A,5) + F1(B,C,D) + E + SHA1t->edata[i] + (uint32_t)0x6ED9EBA1;	
			E = D;
			D = C;
			C = Sn(B,30);
			B = A;
			A = temp;
		}

		for(;i<60;i++)
		{
			temp = Sn(A,5) + F2(B,C,D) + E + SHA1t->edata[i] + (uint32_t)0x8F1BBCDC;
			E = D;
			D = C;
			C = Sn(B,30);
			B = A;
			A = temp;
		}
				
		for(;i<80;i++)
		{
			temp = Sn(A,5) + F3(B,C,D) + E + SHA1t->edata[i] + (uint32_t)0xCA62C1D6;	
			E = D;
			D = C;
			C = Sn(B,30);
			B = A;
			A = temp;
		}
			
		SHA1t->H0 += A;
		SHA1t->H1 += B;
		SHA1t->H2 += C;
		SHA1t->H3 += D;
		SHA1t->H4 += E;				
	}
}

/*
  @Fuction: SHA1_extend
  @Param: struct SHA1_t *SHA1t: some information about SHA1
  @Return: void
  @Description: extend SHA1 data from 16(uint32_t) to 80(uint32_t)
*/
void SHA1_extend(struct SHA1_t *SHA1t)
{
	uint32_t i,tmp;
	
	if(SHA1t)
	{
		for(i=0;i<16;i++)
			SHA1t->edata[i] = ByteToInt(SHA1t->data+i*4);
//			SHA1t->edata[i] = (SHA1t->data[i*4]<<24)|(SHA1t->data[i*4+1]<<16)|(SHA1t->data[i*4+2]<<8)|(SHA1t->data[i*4+3]);
		for(;i<80;i++)
		{
			tmp = SHA1t->edata[i-3]^SHA1t->edata[i-8]^SHA1t->edata[i-14]^SHA1t->edata[i-16];
			SHA1t->edata[i] = (tmp<<1)|(tmp>>31); //lol
		}
	}
}
