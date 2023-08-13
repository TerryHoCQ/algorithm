#include "RSA.h"
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <assert.h>
using std::string;

#define HIDWORD(X) (*((uint32_t*)&(X)+1))
#define LODWORD(X) (*((uint32_t*)&(X)))
#define ResInt(X)  ((4-(X&0x3))&0x3)  //ex: X=35, 35*4=8бнбн3  return (4-3) 
#define CeilInt(X) ((X+3)&0xFFFFFFFC) //ex: X=78, 78*4=19бнбн2  return (19+1)

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

static int rsa_byte_len(char* hex_str)
{
	char* cur = hex_str;
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

static uint8_t* rsa_byte_init(char* hex_str)
{
	char tmp[3] = { 0 };
	char* cur = hex_str;
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

big_number RSAc::m_one = big_number("1");

RSAc::RSAc(string msg, string key, string N)
{
	this->m_msg = new big_number(msg);
	this->m_key = new big_number(key);
	this->m_N = new big_number(N);
	this->m_result = new big_number(nullptr, N.length());
	this->m_result->add(&m_one);
	this->calc_mkn();
}

RSAc::RSAc(uint8_t *msg, int msg_len, uint8_t *key, int key_len, uint8_t *N, int N_len)
{
	this->m_msg = new big_number(msg, msg_len);
	this->m_key = new big_number(key, key_len);
	this->m_N = new big_number(N, N_len);
	this->m_result = new big_number(nullptr, N_len * 2);
	this->m_result->add(&m_one);
	this->calc_mkn();
}

RSAc::RSAc(big_number * msg, big_number * key, big_number * N)
{
	this->m_msg = msg->copy();
	this->m_key = key->copy();
	this->m_N = N->copy();
	this->m_result = new big_number(nullptr, N->m_size * 4);
	this->m_result->add(&m_one);
	this->calc_mkn();
}

RSAc::~RSAc()
{
	if (m_msg != nullptr) delete(m_msg);
	if (m_key != nullptr) delete(m_key);
	if (m_N != nullptr) delete(m_N);
	if (m_result != nullptr) delete(m_result);
}

big_number::big_number(uint8_t * data, int data_len) : m_bnd(nullptr), m_size(data_len)
{
	assert(data_len > 0);

	if (data != nullptr)
	{
		this->m_bnd = format_byte(data, &this->m_size);
		assert(m_bnd != nullptr);
	}
	else
	{
		this->m_bnd = (uint32_t*)malloc(CeilInt(data_len));
		assert(this->m_bnd != nullptr);
		this->m_size = CeilInt(data_len) / 4;
		memset(this->m_bnd, 0, this->m_size * 4);
	}
}

big_number::big_number(string hex_str) : m_bnd(nullptr), m_size(rsa_byte_len((char*)hex_str.c_str()))
{
	uint8_t *data = rsa_byte_init((char*)hex_str.c_str());
	assert(data != nullptr);
	m_bnd = format_byte(data, &m_size);
	assert(m_bnd != nullptr);
	free(data);
}

big_number::~big_number()
{
	if (this->m_bnd != nullptr) free(this->m_bnd);
}

big_number* big_number::copy()
{
	assert(this->m_size > 0 && this->m_bnd != nullptr);
	big_number* new_copy = new big_number(NULL, this->m_size * 4);
	assert(new_copy != nullptr);
	memcpy(new_copy->m_bnd, this->m_bnd, this->m_size * 4);
	return new_copy;
}

int RSAc::calc_mkn()
{
	int i, j, len=0;
	uint8_t mask;
	uint8_t *pdata = (uint8_t*)m_key->m_bnd;

	for (i = m_key->m_size * 4 - 1; i >= 0; i--)
	{
		if (pdata[i] != 0)
		{
			len = i + 1;
			pdata = &pdata[i];
			break;
		}	
	}
	for (i = 0; i < len; i++)
	{
		mask = 0x80;
		for (j = 0; j < 8; j++)
		{
			m_result->mul(m_result);
			m_result->mod(m_N);
			if ((*pdata) & mask)
			{
				m_result->mul(m_msg);
				m_result->mod(m_N);
			}
			mask >>= 1;
		}
		pdata--;
	}
	return 1;
}

void big_number::copy_from(big_number* bn)
{
	assert(bn->m_bnd != nullptr && bn->m_size > 0);
	if (this->m_size != bn->m_size)
	{
		uint32_t *tmp = (uint32_t*)realloc(m_bnd, bn->m_size * 4);
		assert(tmp != nullptr);
		this->m_bnd = tmp;
		this->m_size = bn->m_size;
	}
	memcpy(this->m_bnd, bn->m_bnd, bn->m_size * 4);
}

int big_number::add(big_number * bn)
{
	int i, max_size;
	uint32_t tmpa, tmpb;
	uint64_t tmp;

	assert(bn != nullptr);
	assert(this->m_bnd != nullptr && this->m_size > 0);
	assert(bn->m_bnd != nullptr && bn->m_size > 0);

	max_size = this->m_size < bn->m_size ? bn->m_size : this->m_size;
	big_number *dst = new big_number(NULL, max_size * 4 + 4);

	for (i = 0; i < max_size; i++)
	{
		tmpa = i >= this->m_size ? 0 : this->m_bnd[i];
		tmpb = i >= bn->m_size ? 0 : bn->m_bnd[i];
		//			printf("%.8X %.8X\n",tmpa,tmpb);
		tmp = (uint64_t)tmpa + (uint64_t)tmpb;
		dst->m_bnd[i] += LODWORD(tmp);
		dst->m_bnd[i + 1] += HIDWORD(tmp);
	}
	this->copy_from(dst);
	delete(dst);
	return 1;
}

int big_number::mul(big_number * bn)
{
	uint32_t carry;
	int i, j;
	uint64_t res;
	
	assert(bn != nullptr);
	assert(this->m_bnd != nullptr && this->m_size > 0);
	assert(bn->m_bnd != nullptr && bn->m_size > 0);

	big_number *dst = new big_number(NULL, (this->m_size + bn->m_size) * 4);
	for (i = 0; i < this->m_size; i++)
	{
		carry = 0;
		for (j = 0; j < bn->m_size; j++)
		{
			res = (uint64_t)(this->m_bnd[i]) * (uint64_t)(bn->m_bnd[j]) + carry + dst->m_bnd[i + j];
			dst->m_bnd[i + j] = LODWORD(res);
			carry = HIDWORD(res);
		}
		dst->m_bnd[i + j] = carry;
	}

	this->copy_from(dst);
	delete(dst);
	return 1;
}

int big_number::mod(big_number * bn)
{
	int i, j;
	uint32_t ys, sg, carry;
	uint64_t res;

	assert(bn != nullptr);
	assert(this->m_bnd != nullptr && this->m_size > 0);
	assert(bn->m_bnd != nullptr && bn->m_size > 0);

	big_number *dst = this->copy();
	res = dst->m_bnd[this->m_size - 1];
	for (i = this->m_size - 1; i >= bn->m_size - 1; i--, res = *(uint64_t*)(dst->m_bnd + i))
	{
		if (bn->m_bnd[bn->m_size - 1] == 0)
			continue;
		sg = (uint32_t)(res / bn->m_bnd[bn->m_size - 1]);
		ys = (uint32_t)(res % bn->m_bnd[bn->m_size - 1]);

		/* compute factor */
		while (1)
		{
			res = (uint64_t)sg * (uint64_t)bn->m_bnd[bn->m_size - 2];
			if (HIDWORD(res) < ys) 
				break;
			if (HIDWORD(res) == ys && LODWORD(res) <= dst->m_bnd[i - 1]) 
				break;
			sg--;
			res = (uint64_t)bn->m_bnd[bn->m_size - 1] + (uint64_t)ys;
			if (res & 0xFFFFFFFF00000000)
				break;
			ys = LODWORD(res);
		}
		if (sg == 0) 
			continue;

		carry = 0;
		for (j = 0; j < bn->m_size; j++)
		{
			res = (uint64_t)sg * (uint64_t)bn->m_bnd[j] + carry;
			carry = dst->m_bnd[i + j + 1 - bn->m_size] < LODWORD(res) ? 1 : 0;
			dst->m_bnd[i + j + 1 - bn->m_size] -= LODWORD(res);
			carry += HIDWORD(res);
}

		if (dst->m_bnd[i + j + 1 - bn->m_size] >= carry)
		{
			dst->m_bnd[i + j + 1 - bn->m_size] -= carry;
		}
		else
		{
			dst->m_bnd[i + j + 1 - bn->m_size] = 0;
			res = 0;
			for (j = 0; j < bn->m_size; j++)
			{
				res = (uint64_t)dst->m_bnd[i + j + 1 - bn->m_size] + (uint64_t)bn->m_bnd[j] + HIDWORD(res);
				dst->m_bnd[i + j + 1 - bn->m_size] = LODWORD(res);
			}
		}
	}

	this->copy_from(dst);
	if (this->m_size > bn->m_size)
	{
		this->m_size = bn->m_size;
	}
	delete(dst);
	return 1;
}

string big_number::hex_str()
{
	int i;
	assert(this->m_size > 0 && this->m_bnd != nullptr);

	uint8_t *pdata = (uint8_t*)(this->m_bnd);
	char *pstr = (char*)malloc(this->m_size * 4 * 2 + 1);
	assert(pstr != nullptr);
	memset(pstr, 0, this->m_size * 4 * 2 + 1);

	char *tmp = pstr;
	bool head_0 = true;
	for (i = this->m_size * 4 - 1; i >= 0; i--)
	{
		if (head_0 && pdata[i] == 0)
		{
			continue;
		}
		sprintf(tmp, "%02X", pdata[i]);
		tmp += 2;
		head_0 = false;
	}
	string ret = string(pstr);
	free(pstr);
	return ret;
}

string big_number::hex_bytes()
{
	int i;
	assert(this->m_size > 0 && this->m_bnd != nullptr);

	uint8_t *pdata = (uint8_t*)(this->m_bnd);
	uint8_t *pbytes = (uint8_t*)malloc(this->m_size * 4);
	assert(pbytes != nullptr);
	memset(pbytes, 0, this->m_size * 4);

	uint8_t *tmp = pbytes;
	bool head_0 = true;
	for (i = this->m_size * 4 - 1; i >= 0; i--)
	{
		if (head_0 && pdata[i] == 0)
		{
			continue;
		}
		*tmp++ = pdata[i];
		head_0 = false;
	}
	string ret = string((char*)pbytes, tmp - pbytes);
	free(pbytes);
	return ret;
}

#if 0
#include <Windows.h>
void test1()
{
	srand(10001);
	int i, j;
	uint8_t src1[16], src2[16];
	for (j = 0; j < 16; j++)
	{
		src1[j] = rand() & 0xFF;
	}
	big_number *bn_src1 = new big_number(src1, 16);
	long time = GetTickCount64();
	for (i = 0; i < 10000; i++)
	{
		for (j = 0; j < 16; j++)
		{
			src2[j] = rand() & 0xFF;
		}
		big_number *bn_src2 = new big_number(src2, 16);
		//bn_src1->add(bn_src2);
		bn_src1->mul(bn_src2);
		bn_src2->mod(bn_src1);
		delete(bn_src2);
	}
	printf("time: %lld\n", GetTickCount64() - time);
}

int main()
{
	//test1();
	//RSAc tmp("30313233343536373839", "57FB56C8BB7A19F11417E443089816F58FA0FB0053F6A77D09790F8032358E8D", "83E6B7C0E8631DFEFE32365FA2A5FEAB212EDDB9EA1C1D5E66580D72E728D7C9");
	//printf("%s\n", tmp.get_result()->hex().c_str());

	big_number *src1 = new big_number("1234afb8");
	big_number *src2 = new big_number("53F6A77D09790F8032358E8D");
	src1->add(src2);
	printf("%s\n", src1->hex().c_str());
}

#endif
