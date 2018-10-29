/*Code Amir Hossein Alikhah Mishamandani, 2018, MIT licence */
/*  Distributed for free and with no warranty  */

#ifndef __BIP32_H__
#define __BIP32_H__
#include <stdint.h>
typedef struct {
	uint8_t chain_code[32];
	uint8_t private_key[64];
	uint8_t public_key[32];
	uint8_t child_private_key[32];
	uint8_t child_public_key[32];
	uint8_t Extended_private_key[64];
	uint8_t K_L[32];
	uint8_t K_R[32];
	uint8_t Z_L[32];
	uint8_t Z_R[32];	
} HDNode;

void Init_hdnode(const char *seed, HDNode *inout);
void hdnode_public_key(HDNode *node);
void hdnode_private_child_key(HDNode *inout, uint32_t i);
void hdnode_public_child_key(HDNode *inout, uint32_t i);
#endif