/*Code Amir Hossein Alikhah Mishamandani, 2018, MIT licence */
/*  Distributed for free and with no warranty  */

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "utils.h"
#include "hmac-sha/hmac.h"
void printBits(size_t const size, void const * const ptr){
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

void serialize_index32(uint8_t *out, uint32_t index){
		out[3] = index >> 24;
		out[2] = index >> 16;
		out[1] = index >> 8;
		out[0] = index;
}

void multiply(uint8_t *dst, uint8_t *src, int bytes){
	int i;
	uint8_t prev_acc = 0;
	for (i = 0; i < bytes; i++) {
		dst[i] = (src[i] << 3) + (prev_acc & 0x7);
		prev_acc = src[i] >> 5;
	}
	dst[bytes] = src[bytes-1] >> 5;
}

void add_256bits(uint8_t *dst, uint8_t *src1, uint8_t *src2){
	int i; uint8_t carry = 0;
	for (i = 0; i < 32; i++) {
		uint8_t a = src1[i];
		uint8_t b = src2[i];
		uint16_t r = (uint16_t) a + (uint16_t) b + (uint16_t) carry;
		dst[i] = r & 0xff;
		carry = (r >= 0x100) ? 1 : 0;
	}
}

void scalar_add(const uint8_t *src1, const uint8_t *src2, uint8_t *res){
    uint16_t r = 0; int i;
    for (i = 0; i < 32; i++) {
	    r = (uint16_t) src1[i] + (uint16_t) src2[i] + r;
	    res[i] = (uint8_t) r;
	    r >>= 8;
    }
}

void printbuffer(const char *caption,const uint8_t *buffer, uint32_t buffersize){
	uint32_t s = 0;
	s = buffersize;
	printf("%s",caption);
	for(int j = 0; j < buffersize; j++){
		printf("%2.2x", buffer[j]);
		}
	printf("\n");
}

void Z_Normal_Hardened(const uint8_t *chain_code, const uint8_t *public_key, const uint8_t *Extended_private_key, uint8_t *out, const uint32_t i){
	uint8_t data[4];
	serialize_index32(data, i);
	if (i < 2147483648){ 
		HMAC_SHA512_CTX t1;
		hmac_sha512_Init(&t1, chain_code, (const uint32_t) 32);
		hmac_sha512_Update(&t1, (const uint8_t *) "0x02", (const uint32_t) sizeof("0x02"));
		hmac_sha512_Update(&t1, public_key, 32);
		hmac_sha512_Update(&t1, data, 4);
		hmac_sha512_Final(&t1, out);
	}if (i >= 2147483648 && i <= 4294967295){
		HMAC_SHA512_CTX t2;
		hmac_sha512_Init(&t2, chain_code, (const uint32_t) 32);
		hmac_sha512_Update(&t2, (const uint8_t *) "0x00", (const uint32_t) sizeof("0x00"));
		hmac_sha512_Update(&t2, Extended_private_key, (const uint32_t) 64);
		hmac_sha512_Update(&t2, data, 4);
		hmac_sha512_Final(&t2, out);	
	}
}	

void CC_Normal_Hardened(const uint8_t *chain_code, const uint8_t *public_key, const uint8_t *Extended_private_key, uint8_t *out, const uint32_t i){
	uint8_t data[4];
	serialize_index32(data, i);
	if (i < 2147483648){ 
		HMAC_SHA512_CTX t3;
		hmac_sha512_Init(&t3, chain_code, (const uint32_t) 32);
		hmac_sha512_Update(&t3, (const uint8_t *) "0x03", (const uint32_t) sizeof("0x03"));
		hmac_sha512_Update(&t3, public_key, (const uint32_t) 32);
		hmac_sha512_Update(&t3, data, 4);
		hmac_sha512_Final(&t3, out);
	}if (i >= 2147483648 && i <= 4294967295){
		HMAC_SHA512_CTX t4;
		hmac_sha512_Init(&t4, chain_code, (const uint32_t) 32);
		hmac_sha512_Update(&t4, (const uint8_t *) "0x01", (const uint32_t) sizeof("0x01"));
		hmac_sha512_Update(&t4, Extended_private_key, (const uint32_t) 64);
		hmac_sha512_Update(&t4, data, 4);
		hmac_sha512_Final(&t4, out);	
	}
}