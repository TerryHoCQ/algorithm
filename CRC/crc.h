#ifndef __CRC_H__
#define __CRC_H__
#include <stdio.h>

int CRC8(unsigned char* data, int size);
int CRC16(unsigned char* data, int size);
int CRC32(unsigned char* data, int size);

#endif