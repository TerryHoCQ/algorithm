/*
  @Date: 2018/12/10
  @Version: 1.1.0
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
	1.0.2: Optimized structure
	2023/7/16 - v1.1.0: add class
*/
#ifndef ALGORITHM_RSA_H_
#define ALGORITHM_RSA_H_

#include<string>
using std::string;

#define RSADec RSAc::RSA_dec
#define RSAEnc RSAc::RSA_enc

class big_number
{
public:
	big_number(uint8_t *data, int data_len);
	big_number(string hex_str);
	~big_number();
	int add(big_number *bn);
	//int sub(big_number *bn);
	int mul(big_number *bn);
	int mod(big_number *bn);
	big_number* copy();
	void copy_from(big_number* bn);
	string hex_str();
	string hex_bytes();

	uint32_t* m_bnd;   /*big number data, reverse order*/
	uint32_t m_size;   /*how many dword of bn*/
};

class RSAc
{
public:
	/*
		calculate msg^key%N
		msg, key and N is hex char list, such as string e = "10003";
		when encrypt, plain^pub_key%N
		when decrypt, cipher^pri_key%N
	*/
	RSAc(string msg, string key, string N);
	/*
		calculate msg^key%N
		msg, key and N is bytes list, such as uint8_t e[] = {0x01, 0x00, 0x03};
		when encrypt, plain^pub_key%N
		when decrypt, cipher^pri_key%N
	*/
	RSAc(uint8_t *msg, int msg_len, uint8_t *key, int key_len, uint8_t *N, int N_len);

	RSAc(big_number *msg, big_number *key, big_number *N);

	~RSAc();

	big_number *get_msg() { return m_msg; }
	big_number *get_key() { return m_key; }
	big_number *get_N() { return m_N; }
	big_number *get_result() { return m_result; }

	static big_number *RSA_dec(string msg, string key, string N) { RSAc *rsa = new RSAc(msg, key, N); big_number *res = rsa->get_result()->copy(); delete(rsa); return res; }
	static big_number *RSA_enc(string msg, string key, string N) { return RSAc::RSA_dec(msg, key, N); }
	static big_number *RSA_dec(uint8_t *msg, int msg_len, uint8_t *key, int key_len, uint8_t *N, int N_len) { RSAc *rsa = new RSAc(msg, msg_len, key, key_len, N, N_len); big_number *res = rsa->get_result()->copy(); delete(rsa); return res; }
	static big_number *RSA_enc(uint8_t *msg, int msg_len, uint8_t *key, int key_len, uint8_t *N, int N_len) { return RSAc::RSA_dec(msg, msg_len, key, key_len, N, N_len); }
	static big_number *RSA_dec(big_number *msg, big_number *key, big_number *N) { RSAc *rsa = new RSAc(msg, key, N); big_number *res = rsa->get_result()->copy(); delete(rsa); return res; }
	static big_number *RSA_enc(big_number *msg, big_number *key, big_number *N) { return RSAc::RSA_dec(msg, key, N); }
private:
	big_number *m_msg;
	big_number *m_key;
	big_number *m_N;
	big_number *m_result;
	int calc_mkn();
	static big_number m_one;
};

#endif	//ALGORITHM_RSA_H_
