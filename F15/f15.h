#ifndef __F15_H__
#define __F15_H__
#include <stdint.h>

void setKPC(uint8_t* ki, uint8_t* opc);
void setRC(int n, uint8_t* c, uint8_t r);
void f1(uint8_t* rand, uint8_t* input, uint8_t* MAC_A);
void f1start(uint8_t* rand, uint8_t* input, uint8_t* MAC_S);
void f2(uint8_t* rand, uint8_t* RES);
void f3(uint8_t* rand, uint8_t* CK);
void f4(uint8_t* rand, uint8_t* IK);
void f5(uint8_t* rand, uint8_t* AK);
void f5star(uint8_t* rand, uint8_t* AK);

#endif
