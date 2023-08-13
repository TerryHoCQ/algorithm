/*
  @Date: 2018/12/10
  @Version: 1.0.2
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
  2022/1/11 - v1.0.2: add something
*/

#include "RSA.h"
#include <stdio.h>
#include <stdint.h>

#define HIDWORD(X) (*((uint32_t*)&(X)+1))
#define LODWORD(X) (*((uint32_t*)&(X)))
#define ByteToInt(X) ((*((uint8_t*)X)<<24)|(*((uint8_t*)X+1)<<16)|(*((uint8_t*)X+2)<<8)|(*((uint8_t*)X+3)))
#define ResInt(X)  ((4-(X&0x3))&0x3)  //ex: X=35, 35*4=8……3  return (4-3) 
#define CeilInt(X) ((X+3)&0xFFFFFFFC) //ex: X=78, 78*4=19……2  return (19+1)
#define MakeQword(X,Y) ((((uint64_t)(X))<<32)|(Y))

static uint32_t bseq(uint8_t* seq, struct bn_t* bnt);
static void bcpy(struct bn_t* dst, struct bn_t* src);
static uint8_t byte_reverse(uint8_t* data, uint16_t length);
static uint32_t* format_byte(uint8_t* data, uint32_t* len);

void print_bn(struct bn_t* bn)
{
	int i;
	uint8_t* tmp;

	if (bn->size > 0)
	{
		tmp = (uint8_t*)(bn->bnd);
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
  @Return: int, success is 1,other is 0
  @Description: decoder cipherText by RSA arithmetic
				the size of decrypt data must more than Nsize, otherwise may be error
				RSA_t data format is big end
				example:
				input[] = {0x30,0x31,0x32,0x33,0x34,0x35};
				len = 6;
				the actual bn is 0x303132333435
*/
int RSA(struct RSA_t* RSAt)
{
	struct bn_t* bn_n, * bn_ct, * bn_mul;
	int i, j, out_len;
	uint8_t* out;
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
			out_len = bn_mul->size * 4;
			/*
			//寻找第一个不是0的位置
			out = (uint8_t*)bn_mul->bnd + bn_mul->size * 4 - 1;
			while (*out == 0)
			{
				out_len--;
				out--;
			}
			if (out_len > RSAt->PTsize)
			{
				bfree(bn_ct);
				bfree(bn_n);
				bfree(bn_mul);
				return 0;
			}
			*/

			memcpy(RSAt->plainText, bn_mul->bnd, out_len);
			RSAt->PTsize = out_len;

			byte_reverse(RSAt->plainText, out_len);

			bfree(bn_ct);
			bfree(bn_n);
			bfree(bn_mul);
			return 1;
		}
	}
	return 0;
}

/*
  @Fuction: bmul
  @Param: struct bn_t *src_dst: input and output
		  struct bn_t *src: input
  @Return: int, if function is successful,return 1, otherwise return 0
  @Description: calculate c=a*b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
int bmul(struct bn_t* src_dst, struct bn_t* src)
{
	struct bn_t* c;
	uint32_t carry, * aptr, * bptr, * cptr;
	int i, j;
	uint64_t res;

	if (src_dst && src)
	{
		if (!src_dst->bnd || !src->bnd || !src_dst->size || !src->size) return 0;
		aptr = src_dst->bnd; /* Reduce the length of the addressing instruction */
		bptr = src->bnd;

		c = binit(NULL, (src_dst->size + src->size) * 4);
		if (!c) return 0;
		cptr = c->bnd;
		memset(cptr, 0, c->size * 4);

		for (i = 0; i < src_dst->size; i++)
		{
			carry = 0;
			for (j = 0; j < src->size; j++)
			{
				res = (uint64_t)aptr[i] * (uint64_t)bptr[j] + carry + cptr[i + j];
				cptr[i + j] = LODWORD(res);
				carry = HIDWORD(res);
			}
			cptr[i + j] = carry;
		}

		bcpy(c, src_dst);
		bfree(c);
		return 1;
	}
	return 0;
}
/*
  @Fuction: bmod
  @Param: struct bn_t *src_dst: input and output
		  struct bn_t *src: input
  @Return: int, if function is successful,return 1, otherwise return 0
  @Description: calculate c=a%b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
int bmod(struct bn_t* src_dst, struct bn_t* src)
{
	int i, j, blen;
	uint32_t ys, sg, carry, * bptr, * tmp;
	uint64_t res;

	if (src_dst && src)
	{
		if (!src_dst->bnd || !src->bnd || !src_dst->size || !src->size) return 0;
		blen = src->size; /* Reduce the length of the addressing instruction */
		bptr = src->bnd;

		tmp = (uint32_t*)malloc(src_dst->size * sizeof(uint32_t*));
		if (!tmp) return 0;
		memcpy(tmp, src_dst->bnd, src_dst->size * sizeof(uint32_t*));

		res = tmp[src_dst->size - 1];
		for (i = src_dst->size - 1; i >= blen - 1; i--, res = *(uint64_t*)(tmp + i))//res = *(uint64_t*)(tmp+i)  res = MakeQword(tmp[i],tmp[i+1])
		{
			sg = (uint32_t)(res / bptr[blen - 1]);
			ys = (uint32_t)(res % bptr[blen - 1]);

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

		if (src_dst->size != blen)
		{
			free(src_dst->bnd);
			src_dst->bnd = (uint32_t*)malloc(blen * sizeof(uint32_t));
		}
		if (!src_dst->bnd) return 0;
		memcpy(src_dst->bnd, tmp, blen * sizeof(uint32_t));
		src_dst->size = blen;

		free(tmp);
		return 1;
	}
	return 0;
}

/*
  @Fuction: byte_reverse
  @Param: uint8_t *data: input and output, the data want to be reverse
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
static uint8_t byte_reverse(uint8_t* data, uint16_t length)
{
	int i;
	uint8_t* ptr;

	if (length <= 0)
		return 0;

	ptr = (uint8_t*)malloc(length);
	if (!ptr)
		return 0;

	memcpy(ptr, data, length);

	ptr += length;
	for (i = 0; i < length; i++)
		*data++ = *--ptr;

	free(ptr);
	return 1;
}

/*
  @Fuction: badd
  @Param: struct bn_t *src1: input
		  struct bn_t *src2: input
  @Return: struct bn_t *, if function is successful,
		   then return a pointer to a bn_t, otherwise return NULL
		   [size of output should be 4 more than the max size of a and b]
  @Description: calculate c=a+b
				all input and output is hex text view
				ex:when input sequence is {01,02,03,04}, it equal 0x01020304
*/
struct bn_t* badd(struct bn_t* src1, struct bn_t* src2)
{
	int i, maxSize;
	struct bn_t* c;
	uint32_t * aptr, * bptr, * cptr, tmpa, tmpb;
	uint64_t tmp;

	if (src1 && src2)
	{
		if (!src1->bnd || !src2->bnd || !src1->size || !src2->size) return NULL;
		aptr = src1->bnd;/* Reduce the length of the addressing instruction */
		bptr = src2->bnd;

		maxSize = src1->size < src2->size ? src2->size : src1->size;

		c = binit(NULL, maxSize * 4 + 4);
		if (!c) return NULL;
		cptr = c->bnd;
		memset(cptr, 0, c->size * 4);

		for (i = 0; i < maxSize; i++)
		{
			tmpa = i >= src1->size ? 0 : aptr[i];
			tmpb = i >= src2->size ? 0 : bptr[i];
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
  @Fuction: format_byte
  @Param: uint8_t *data: data
		  uint32_t *len: how many bytes of a when input,
						 if length is not a multiple of 4 and fuction success,
						 it will be changed adapt to a multiple of 4,
						 how many dword of ret pointer when output
  @Return: if function failed,return 0,
			otherwise malloc size(%4 = 0) of data, it must be free when unused
  @Description: when length of a is not a multiple of 4,
				then function will make size a multiple of 4,
				and malloc a memory for a copy of a,
				the front padding will be filled 0,
				example:
					before formatByte:
					data[] = {0x30,0x31,0x32,0x33,0x34,0x35};
					len = 6;
					after formatByte:
					return[] = {0x35,0x34,0x33,0x32,0x31,0x30,0x00,0x00} = {0x32333435,0x00003031} = 0x0000303132333435
*/
static uint32_t* format_byte(uint8_t* data, uint32_t* len)
{
	uint32_t start, size, * buff;

	if (!len || !data) return NULL;

	start = ResInt(*len);
	size = CeilInt(*len); /*size is a multiple of 4*/

	buff = (uint32_t*)malloc(size);
	if (!buff) return NULL;

	/* front padding 0 */
	memset(buff, 0, start);
	memcpy((uint8_t*)buff + start, data, *len);
	byte_reverse((uint8_t*)buff, size);
	*len = size / 4;
	return buff;
}

/*
  @Fuction: binit
  @Param: uint8_t *bn_data: big number data requence
		  uint32_t size: how mant bytes of bnSeq
  @Return: struct bn_t*, a pointer to a inited bn_t
  @Description: must call bdeit function when unused
*/
struct bn_t* binit(uint8_t* bn_data, uint32_t size)
{
	struct bn_t* bnt;

	if (!size) return NULL;
	bnt = (bn_t*)malloc(sizeof(struct bn_t));
	if (!bnt) return NULL;

	if (bn_data)
	{
		bnt->bnd = format_byte(bn_data, &size);
		bnt->size = size;
	}
	else
	{
		bnt->bnd = (uint32_t*)malloc(CeilInt(size));
		if (!bnt->bnd) return NULL;
		bnt->size = CeilInt(size) / 4;
		memset(bnt->bnd, 0, bnt->size * 4);
	}
	return bnt;
}

/*
  @Fuction: bdeit
  @Param: struct bn_t* bn: a pointer to a bn_t that will be deinit
  @Return: int, if function success, return 1, otherwise return 0
  @Description: the function must be called when a bn_t unused
*/
int bfree(struct bn_t* bn)
{
	if (!bn) return 0;
	if (bn->bnd) free(bn->bnd);
	free(bn);
	return 1;
}

/*
  @Fuction: bseq
  @Param: uint8_t *seq: output
		  struct bn_t* bnt: input
  @Return: uint32_t, if function success, then return how many bytes of seq, otherwise return 0
  @Description: get sequence form bn_t
*/
static uint32_t bseq(uint8_t* seq, struct bn_t* bnt)
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
				byte_reverse(seq, i + 1);
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
static void bcpy(struct bn_t* a, struct bn_t* b)
{
	if (a->size == b->size)
	{
		if (!b->bnd) b->bnd = (uint32_t*)malloc(a->size * sizeof(uint32_t));
		if (a->bnd && b->bnd) memcpy(b->bnd, a->bnd, a->size * sizeof(uint32_t));
	}
	else
	{
		if (b->bnd) free(b->bnd);
		b->bnd = (uint32_t*)malloc(a->size * sizeof(uint32_t));
		if (a->bnd && b->bnd) memcpy(b->bnd, a->bnd, a->size * sizeof(uint32_t));
		b->size = a->size;
	}

}

int rsa_byte_len(char* hex)
{
	char* cur = hex;
	if (cur == nullptr)
	{
		return 0;
	}

	if (cur[0] == '0' && cur[1] == 'x')
	{
		cur += 2;
	}

	return (strlen(cur) + 1) / 2;
}

uint8_t* rsa_byte_init(char* hex)
{
	char tmp[3] = { 0 };
	char* cur = hex;
	int len;
	uint8_t* byte, *dst;

	if (cur[0] == '0' && cur[1] == 'x')
	{
		cur += 2;
	}

	len = rsa_byte_len(cur);
	dst = byte = (uint8_t*)malloc(len);
	if (byte == nullptr)
	{
		return nullptr;
	}

	if (strlen(cur) % 2 != 0)
	{
		tmp[0] = '0';
		tmp[1] = cur[0];
		tmp[2] = 0;
		dst[0] = (uint8_t)strtol(tmp, NULL, 16);
		dst++;
		cur++;
	}

	while (cur[0] != 0)
	{
		tmp[0] = cur[0];
		tmp[1] = cur[1];
		tmp[2] = 0;
		dst[0] = (uint8_t)strtol(tmp, NULL, 16);
		dst++;
		cur += 2;
	}

	return byte;
}

void rsa_byte_free(uint8_t* byte)
{
	if (byte)
		free(byte);
}

int RSA_enc(void* cipher, int cipher_len, void* plain, int plain_len, char* key, char* n)
{
	uint8_t* key_byte = nullptr, * n_byte = nullptr;
	int key_len, n_len, ret;
	RSA_t RSAt;

	key_len = rsa_byte_len(key);
	n_len = rsa_byte_len(n);

	key_byte = rsa_byte_init(key);
	n_byte = rsa_byte_init(n);

	RSAt.key = key_byte;
	RSAt.Ksize = key_len;
	RSAt.n = n_byte;
	RSAt.Nsize = n_len;
	RSAt.cipherText = (uint8_t*)plain;
	RSAt.CTsize = plain_len;
	RSAt.plainText = (uint8_t*)cipher;
	RSAt.PTsize = cipher_len;

	if (RSA(&RSAt) == 0)
	{
		ret = 0;
	}
	else
	{
		ret = RSAt.PTsize;
	}

	rsa_byte_free(n_byte);
	rsa_byte_free(key_byte);

	return ret;
}

int RSA_dec(void* cipher, int cipher_len, void* plain, int plain_len, char* e, char* n)
{
	uint8_t* e_byte = nullptr, * n_byte = nullptr;
	int e_len, n_len, ret;
	RSA_t RSAt;

	e_len = rsa_byte_len(e);
	n_len = rsa_byte_len(n);

	e_byte = rsa_byte_init(e);
	n_byte = rsa_byte_init(n);

	RSAt.key = e_byte;
	RSAt.Ksize = e_len;
	RSAt.n = n_byte;
	RSAt.Nsize = n_len;
	RSAt.cipherText = (uint8_t*)cipher;
	RSAt.CTsize = cipher_len;
	RSAt.plainText = (uint8_t*)plain;
	RSAt.PTsize = plain_len;

	if (RSA(&RSAt) == 0)
	{
		ret = 0;
	}
	else
	{
		ret = RSAt.PTsize;
	}

	rsa_byte_free(n_byte);
	rsa_byte_free(e_byte);

	return ret;
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
