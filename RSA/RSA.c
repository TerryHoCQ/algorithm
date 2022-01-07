/*
  @Date: 2018/12/10
  @Version: 1.0.1
  @Author: MJS
  @Description:
	RSA decoder
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

#include "RSA.h"
#include <stdio.h>
#include <stdint.h>

void print_bn(struct bn_t* bn)
{
	int i;
	uint8_t* tmp;

	if (bn->size > 0)
	{
		tmp = bn->bnd;
		printf("bn=0x");
		for (i = bn->size * 4 - 1; i >= 0; i--)
		{
			printf("%02X", tmp[i]);
		}
		printf("\n");
	}
}

/*
  @Fuction: RSA
  @Param: RSA_t *RSAt: a pointer to a RSA information
  @Return: uint8_t, success is 1,other is 0
  @Description: decoder cipherText by RSA arithmetic
				the size of decrypt data must more than Nsize, otherwise may be error
				RSA_t data format is big end
				example:
				input[] = {0x30,0x31,0x32,0x33,0x34,0x35};
				len = 6;
				the actual bn is 0x303132333435
*/
uint8_t RSA(struct RSA_t* RSAt)
{
	struct bn_t* bn_n, * bn_ct, * bn_mul;
	int i, j;
	uint8_t mask;

	if (RSAt)
	{
		if (RSAt->CTsize && RSAt->Ksize && RSAt->Nsize)
		{
			bn_ct = binit(RSAt->cipherText, RSAt->CTsize);
			bn_n = binit(RSAt->n, RSAt->Nsize);
			bn_mul = binit(NULL, RSAt->Nsize * 2); //to check: RSAt->Nsize*2
			bn_mul->bnd[0] = 0x1;

			//print_bn(bn_ct);
			//print_bn(bn_n);

			for (i = 0; i < RSAt->Ksize; i++)
			{
				mask = 0x80;
				for (j = 0; j < 8; j++)
				{
					bmul(bn_mul, bn_mul);
					bmod(bn_mul, bn_n);
					if (RSAt->key[i] & mask)
					{
						bmul(bn_mul, bn_ct);
						bmod(bn_mul, bn_n);
					}
					mask >>= 1;
				}
			}
			memcpy(RSAt->plainText, bn_mul->bnd, bn_mul->size * 4);
			RSAt->PTsize = bn_mul->size * 4;
			byteReverse(RSAt->plainText, RSAt->PTsize);

			bdeit(bn_ct);
			bdeit(bn_n);
			bdeit(bn_mul);
			return 1;
		}
	}
	return 0;
}

/*
  @Fuction: bmul
  @Param: struct bn_t *a: input and output
		  struct bn_t *b: input
  @Return: uint8_t, if function is successful,return 1, otherwise return 0
  @Description: calculate c=a*b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
uint8_t bmul(struct bn_t* a, struct bn_t* b)
{
	struct bn_t* c;
	uint32_t carry, * aptr, * bptr, * cptr;
	int i, j;
	uint64_t res;

	if (a && b)
	{
		if (!a->bnd || !b->bnd || !a->size || !b->size) return 0;
		aptr = a->bnd; /* Reduce the length of the addressing instruction */
		bptr = b->bnd;

		c = binit(NULL, (a->size + b->size) * 4);
		if (!c) return 0;
		cptr = c->bnd;
		memset(cptr, 0, c->size * 4);

		for (i = 0; i < a->size; i++)
		{
			carry = 0;
			for (j = 0; j < b->size; j++)
			{
				res = (uint64_t)aptr[i] * (uint64_t)bptr[j] + carry + cptr[i + j];
				cptr[i + j] = LODWORD(res);
				carry = HIDWORD(res);
			}
			cptr[i + j] = carry;
		}

		bcpy(c, a);
		bdeit(c);
		return 1;
	}
	return 0;
}
/*
  @Fuction: bmod
  @Param: struct bn_t *a: input and output
		  struct bn_t *b: input
  @Return: uint8_t, if function is successful,return 1, otherwise return 0
  @Description: calculate c=a%b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
uint8_t bmod(struct bn_t* a, struct bn_t* b)
{
	int i, j;
	uint32_t ys, sg, carry, blen, * bptr, * tmp;
	uint64_t res;

	if (a && b)
	{
		if (!a->bnd || !b->bnd || !a->size || !b->size) return 0;
		blen = b->size; /* Reduce the length of the addressing instruction */
		bptr = b->bnd;

		tmp = malloc(a->size * 4);
		if (!tmp) return 0;
		memcpy(tmp, a->bnd, a->size * 4);

		res = tmp[a->size - 1];
		for (i = a->size - 1; i >= blen - 1; i--, res = *(uint64_t*)(tmp + i))//res = *(uint64_t*)(tmp+i)  res = MakeQword(tmp[i],tmp[i+1])
		{
			sg = res / bptr[blen - 1];
			ys = res % bptr[blen - 1];

			/* compute factor */
			while (1)
			{
				res = (uint64_t)sg * (uint64_t)bptr[blen - 2];
				if (HIDWORD(res) < ys) break;
				if (HIDWORD(res) == ys && LODWORD(res) <= tmp[i - 1]) break;
				sg--;
				res = (uint64_t)bptr[blen - 1] + (uint64_t)ys;
				if (res & 0xFFFFFFFF00000000)
					break;
				ys = LODWORD(res);
			}
			if (sg == 0) continue;

			carry = 0;
			for (j = 0; j < blen; j++)
			{
				res = (uint64_t)sg * (uint64_t)bptr[j] + carry;
				carry = tmp[i + j + 1 - blen] < LODWORD(res) ? 1 : 0;
				tmp[i + j + 1 - blen] -= LODWORD(res);
				carry += HIDWORD(res);
			}

			if (tmp[i + j + 1 - blen] >= carry) tmp[i + j + 1 - blen] -= carry;
			else
			{
				tmp[i + j + 1 - blen] = 0;
				res = 0;
				for (j = 0; j < blen; j++)
				{
					res = (uint64_t)tmp[i + j + 1 - blen] + (uint64_t)bptr[j] + HIDWORD(res);
					tmp[i + j + 1 - blen] = LODWORD(res);
				}
			}
		}

		if (a->size != blen)
		{
			free(a->bnd);
			a->bnd = malloc(blen * 4);
		}
		if (!a->bnd) return 0;
		memcpy(a->bnd, tmp, blen * 4);
		a->size = blen;

		free(tmp);
		return 1;
	}
	return 0;
}

/*
  @Fuction: byteReverse
  @Param: uint8_t *a: input and output, the data want to be reverse
		  uint16_t length: the length of the a;
  @Return: uint8_t, if function is successful, then return 1, otherwise return 0
  @Description:
	reverse the byte of a, and result will copy to a
	example:
	before byteReverse:
	a[] = {0x30,0x31,0x32,0x33,0x34,0x35};
	length = 6;
	after byteReverse:
	a[] = {0x35,0x34,0x33,0x32,0x31,0x30};
*/
uint8_t byteReverse(uint8_t* a, uint16_t length)
{
	int i;
	uint8_t* ptr;

	if (length <= 0)
		return 0;

	ptr = malloc(length);
	if (!ptr)
		return 0;

	memcpy(ptr, a, length);

	ptr += length;
	for (i = 0; i < length; i++)
		*a++ = *--ptr;

	free(ptr);
	return 1;
}

/*
  @Fuction: badd
  @Param: struct bn_t *a: input
		  struct bn_t *b: input
  @Return: struct bn_t *, if function is successful,
		   then return a pointer to a bn_t, otherwise return NULL
		   [size of output should be 4 more than the max size of a and b]
  @Description: calculate c=a+b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
struct bn_t* badd(struct bn_t* a, struct bn_t* b)
{
	struct bn_t* c;
	uint32_t i, * aptr, * bptr, * cptr, maxSize, tmpa, tmpb;
	uint64_t tmp;

	if (a && b)
	{
		if (!a->bnd || !b->bnd || !a->size || !b->size) return NULL;
		aptr = a->bnd;/* Reduce the length of the addressing instruction */
		bptr = b->bnd;

		maxSize = a->size < b->size ? b->size : a->size;

		c = binit(NULL, maxSize * 4 + 4);
		if (!c) return NULL;
		cptr = c->bnd;
		memset(cptr, 0, c->size * 4);

		for (i = 0; i < maxSize; i++)
		{
			tmpa = i >= a->size ? 0 : aptr[i];
			tmpb = i >= b->size ? 0 : bptr[i];
			//			printf("%.8X %.8X\n",tmpa,tmpb);
			tmp = (uint64_t)tmpa + (uint64_t)tmpb;
			cptr[i] += LODWORD(tmp);
			cptr[i + 1] += HIDWORD(tmp);
		}

		return c;
	}
	return NULL;
}

/*
  @Fuction: formatByte
  @Param: uint8_t *a: data
		  uint32_t *len: how many bytes of a when input,
						 if length is not a multiple of 4 and fuction success,
						 it will be changed adapt to a multiple of 4,
						 how many dword of ret pointer when output
  @Return: if function failed,return 0,
			otherwise malloc size(%4 = 0) of a, it must be free when unused
  @Description: when length of a is not a multiple of 4,
				then function will make size a multiple of 4,
				and malloc a memory for a copy of a,
				the front padding will be filled 0,
				example:
					before formatByte:
					a[] = {0x30,0x31,0x32,0x33,0x34,0x35};
					len = 6;
					after formatByte:
					return[] = {0x35,0x34,0x33,0x32,0x31,0x30,0x00,0x00} = {0x32333435,0x00003031} = 0x0000303132333435
*/
uint32_t* formatByte(uint8_t* a, uint32_t* len)
{
	uint32_t start, size, * buff;

	if (!len || !a) return NULL;

	start = ResInt(*len);
	size = CeilInt(*len); /*size is a multiple of 4*/

	buff = malloc(size);
	if (!buff) return NULL;

	/* front padding 0 */
	memset(buff, 0, start);
	memcpy((uint8_t*)buff + start, a, *len);
	byteReverse((uint8_t*)buff, size);
	*len = size / 4;
	return buff;
}

/*
  @Fuction: binit
  @Param: uint8_t *bnSeq: big number data requence
		  uint32_t size: how mant bytes of bnSeq
  @Return: struct bn_t*, a pointer to a inited bn_t
  @Description: must call bdeit function when unused
*/
struct bn_t* binit(uint8_t* bnSeq, uint32_t size)
{
	struct bn_t* bnt;

	if (!size) return NULL;
	bnt = malloc(sizeof(struct bn_t));
	if (!bnt) return NULL;

	if (bnSeq)
	{
		bnt->bnd = formatByte(bnSeq, &size);
		bnt->size = size;
	}
	else
	{
		bnt->bnd = malloc(CeilInt(size));
		if (!bnt->bnd) return NULL;
		bnt->size = CeilInt(size) / 4;
		memset(bnt->bnd, 0, bnt->size * 4);
	}
	return bnt;
}

/*
  @Fuction: bdeit
  @Param: struct bn_t* bnt: a pointer to a bn_t that will be deinit
  @Return: uint8_t, if function success, return 1, otherwise return 0
  @Description: the function must be called when a bn_t unused
*/
uint8_t bdeit(struct bn_t* bnt)
{
	if (!bnt) return 0;
	if (bnt->bnd) free(bnt->bnd);
	free(bnt);
	return 1;
}

/*
  @Fuction: bseq
  @Param: uint8_t *seq: output
		  struct bn_t* bnt: input
  @Return: uint32_t, if function success, then return how many bytes of seq, otherwise return 0
  @Description: get sequence form bn_t
*/
uint32_t bseq(uint8_t* seq, struct bn_t* bnt)
{
	uint8_t* tmp;
	int i;

	if (seq && bnt)
	{
		if (!bnt->bnd || !bnt->size) return 0;

		tmp = (uint8_t*)bnt->bnd;
		for (i = bnt->size * 4 - 1; i >= 0; i--)
		{
			if (tmp[i] != 0)
			{
				memcpy(seq, tmp, i + 1);
				byteReverse(seq, i + 1);
				return 	i + 1;
			}
		}
		memset(seq, 0, bnt->size * 4);
		return bnt->size * 4;
	}
	return 0;
}

/*
	@Fuction: bcpy
	@Param: struct bn_t *a: input big number
			struct bn_t *b: output big number
	@Return: void
	@Description: copy big number form a to b
*/
void bcpy(struct bn_t* a, struct bn_t* b)
{
	if (a->size == b->size)
	{
		if (!b->bnd) b->bnd = malloc(a->size * 4);
		if (a->bnd && b->bnd) memcpy(b->bnd, a->bnd, a->size * 4);
	}
	else
	{
		if (b->bnd) free(b->bnd);
		b->bnd = malloc(a->size * 4);
		if (a->bnd && b->bnd) memcpy(b->bnd, a->bnd, a->size * 4);
		b->size = a->size;
	}

}

#if 0
int main()
{
	int i;
	struct RSA_t RSAt;

	uint8_t key[] = { 0x3D,0x43,0xB6,0x82,0xF0,0x04,0x09,0xDD };// 0x3D43B682F00409DD;
	uint8_t n[] = { 0x54,0x87,0xAF,0xE2,0xEA,0xA3,0x1F,0xE1 };// 0x5487AFE2EAA31FE1;
	uint8_t e[] = { 0x01,0x00,0x01 };// 0x10001;
	uint8_t p[] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37 };// 0x3031323334353637;
	uint8_t c[] = { 0x15,0x74,0x51,0x04,0x9D,0x35,0x66,0xDD };//0x157451049D3566DD;
	uint8_t plain[128];

	RSAt.cipherText = c;
	RSAt.CTsize = sizeof(c);
	RSAt.key = key;
	RSAt.Ksize = sizeof(key);

	RSAt.n = n;
	RSAt.Nsize = sizeof(n);
	RSAt.plainText = plain;
	RSAt.PTsize = sizeof(plain);
	RSA(&RSAt);

	printf("plainText:\n");
	for (i = 0; i < RSAt.PTsize; i++)
	{
		printf("%.2X", RSAt.plainText[i]);
		i % 16 == 15 ? printf("\n") : printf(" ");
	}
	printf("\n");

	system("pause");
}

#endif
