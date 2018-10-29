/*Code Amir Hossein Alikhah Mishamandani, 2018, MIT licence */
/*  Distributed for free and with no warranty  */


#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void printBits(size_t const size, void const * const ptr);
void serialize_index32(uint8_t *out, uint32_t index);
void multiply(uint8_t *dst, uint8_t *src, int bytes);
void add_256bits(uint8_t *dst, uint8_t *src1, uint8_t *src2);
void scalar_add(const uint8_t *src1, const uint8_t *src2, uint8_t *res);
void printbuffer(const char *caption,const uint8_t *buffer, uint32_t buffersize);
void CC_Normal_Hardened(const uint8_t *chain_code,const uint8_t *public_key,const uint8_t *Extended_private_key, uint8_t *out,const uint32_t i);
void Z_Normal_Hardened(const uint8_t *chain_code,const uint8_t *public_key,const uint8_t *Extended_private_key, uint8_t *out,const uint32_t i);

#endif
