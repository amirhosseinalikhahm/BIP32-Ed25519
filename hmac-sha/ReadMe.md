# The Hmac-SHA256 & Hmac-SHA512

This is a C/C++ Implementation of Hmac-SHA256 & Hmac-SHA512 functions. forked from: https://github.com/trezor/trezor-crypto. Distributed with no warranty & for free.

# Example

```C
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "hmac.h"
	
int main(void){

	char* string;
	memset(string, 0,sizeof(string));
	uint8_t SHA256r[32];
	uint8_t SHA512r[64];
	string = "Hello";
	
	hmac_sha256((const uint8_t *) "a", (const uint32_t) strlen("a"), (const uint8_t *) string, (const uint32_t) strlen(string), SHA256r);
	hmac_sha512((const uint8_t *) "a", (const uint32_t) strlen("a"), (const uint8_t *) string, (const uint32_t) strlen(string), SHA512r);
	
	printf("\nThe result of Hmac-SHA256:\n");
	for(int i = 0; i < sizeof(SHA256r); i++){
		printf("%x", SHA256r[i]);
	}
	
	printf("\nThe result of Hmac-SHA512:\n");
	for(int j = 0; j < sizeof(SHA512r); j++){
		printf("%x", SHA512r[j]);
	}
	printf("\n");
}
	

```
