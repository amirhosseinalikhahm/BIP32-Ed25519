# SHA256 & SHA512

This is a C implemenatation of SHA256 & SHA 512. forked from: https://github.com/WaterJuice/WjCryptLib. Distributed for free and with no warranty.

# Example


```C
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "WjCryptLib_Sha256.h"
#include "WjCryptLib_Sha512.h"


	
int main(void){

	char* string;
	SHA256_HASH SHA256r;
	SHA512_HASH SHA512r;
	
	string = "a";
	
	//Sha256Context t1;
	Sha512Context t2;
	
	Sha256Calculate(string, (uint32_t)strlen(string), &SHA256r);
	
	Sha512Initialise(&t2);
	Sha512Update(&t2,string,(uint32_t)strlen(string));
	Sha512Finalise(&t2,&SHA512r);
	
	printf("\nThe result of SHA256:\n");
	for(int i = 0; i < sizeof(SHA256r); i++){
		printf("%2.2x", SHA256r.bytes[i]);
	}
	
	printf("\nThe result of SHA512:\n");
	for(int j = 0; j < sizeof(SHA512r); j++){
		printf("%2.2x", SHA512r.bytes[j]);
	}
	printf("\n");
}
```
