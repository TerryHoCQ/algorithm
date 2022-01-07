#include <stdio.h>
#include <stdint.h>
#include <string.h>

void tbl_calc(int poly, int n)
{
	int i,j,temp;
	
	printf("ploy:0x%X\n",poly);
	for (i=0; i<(1<<n); ++i) //2^n
	{
		temp = i;
		for (j=0;j<n;++j)
		{
			if (temp & 1)
			{
				temp >>= 1;
				temp ^= poly;
			}		
			else
			{
				temp >>= 1; 
			}			
		}
		printf("%02X ", temp);
		if (i%16 == 15)
			printf("\n");
	}
}

void crc8_tbl_calc(int poly)
{
	tbl_calc(poly,8);
} 

void crc4_tbl_calc(int poly)
{
	tbl_calc(poly,4);
}

#if 0
int main(int argc, char **argv)
{
	//crc8_tbl_calc(0x8C); //ploy=x^8+x^5+x^4+x^0(0x131) reverse(0x8C) 
	
	int i;
	for(i=0;i<256;++i)
	{
		crc4_tbl_calc(i);	
	}
		
	
	return 0;
}
#endif

