#ifndef __CRC_H__
#define __CRC_H__
#include <stdio.h>

typedef unsigned char ubit_t;

int CRC8(unsigned char* data, int size);
int CRC16(unsigned char* data, int size);
int CRC32(unsigned char* data, int size);

//±ÈÌØCRC 
int crc_fix(ubit_t *bits, int len, int poly, int width, int init, int xorout);
#define crc8_poly7(x, y) crc_fix(x, y, 0x7, 8, 0, 0)
#define crc10_poly24f(x, y) crc_fix(x, y, 0x24F, 10, 0, 0)

void crc_table(int poly, int width);

#endif
