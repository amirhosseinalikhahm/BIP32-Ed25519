/*Code Amir Hossein Alikhah Mishamandani, 2018, MIT licence */
/*  Distributed for free and with no warranty  */

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>
#include <iostream>
#include <array>
#include "bip32.h"
#include "utils.h"
#include "hash/WjCryptLib_Sha256.h"
#include "hash/WjCryptLib_Sha512.h"
#include "hmac-sha/hmac.h"
#include "ed25519/ed25519.h"
#include "ed25519/ge.h"
#include "ed25519/sc.h"
//Return '1' if the bit value at position y within x is '1' and '0' if it's 0 by ANDing x with a bit mask where the bit in y's position is '1' and '0' elsewhere and comparing it to all 0's.  Returns '1' in least significant bit position if the value of the bit is '1', '0' if it was '0'.
#define READ(x,y) ((0u == (x & (1<<y)))?0u:1u)
#define ALL_DIGITS (-1)

void Init_hdnode(const char *seed, HDNode *inout){
	
	//Initialization
	uint8_t I[32 + 32]; //buffer
	int j; //counter
	memset(inout, 0, sizeof(HDNode));
	memset(inout->chain_code, 0, sizeof(inout->chain_code));
	memset(inout->private_key, 0, sizeof(inout->private_key));
	memset(inout->public_key, 0, sizeof(inout->public_key));
	memset(inout->child_private_key, 0, sizeof(inout->child_private_key));
	memset(inout->child_public_key, 0, sizeof(inout->child_public_key));
	memset(inout->K_L, 0, sizeof(inout->K_L));
	memset(inout->K_R, 0, sizeof(inout->K_R));
	memset(inout->Z_L, 0, sizeof(inout->Z_L));
	memset(inout->Z_R, 0, sizeof(inout->Z_R));
	memset(I, 0, sizeof(I));
	//SHA512_Init_node_from_seed
	SHA512_HASH SHA512r;
	Sha512Context t1;
	Sha512Initialise(&t1);
	Sha512Update(&t1,seed,(uint32_t)strlen(seed));
	Sha512Finalise(&t1,&SHA512r);
	//Copying the SHA512 result to buffer
	memcpy(I,SHA512r.bytes,64);
	//Printing copy operation
	printbuffer("The k[64]: ", I,sizeof(I));
	//checking the private key condition
	if(READ(I[0],5) != 0){printf("\nInvalid Private key ...!\n");exit(0);}	
	//setting the required bits in bytes [0] and [31]
	I[0] &= 0xF8;
    I[31] &= 0x7F;
	I[31] |= 0x40;
	I[31] &= 0xDF;
	//Printing the bits set operation
	printf("The Byte[0] of K_L (if ****000 the value is OK!): ");
	printBits(sizeof(I[0]),&I[0]); // if ****000 the value is OK!
	printf("The Byte[31] of K_L (if 010**** the value is OK!): ");
	printBits(sizeof(I[31]),&I[31]); //if 010**** the value is OK!
	//Exporting the K_L
	memcpy(inout->K_L, I, 32);
	//Printing Private key copy operation
	printbuffer("The K_L: ", inout->K_L,sizeof(inout->K_L));
	//Exporting the K_R
	memcpy(inout->K_R, I + 32, 32);
	//Printing Private key copy operation
	printbuffer("The K_R: ", inout->K_R,sizeof(inout->K_R));
	//Generating the Chain code
	SHA256_HASH SHA256r;
	Sha256Context t2;
	Sha256Initialise(&t2);
	Sha256Update(&t2,"0x01",1);
	Sha256Update(&t2,(const char*) I,64);
	Sha256Finalise(&t2,&SHA256r);
	memcpy(inout->chain_code,SHA256r.bytes,32);
	//Printing the Chain Code
	printbuffer("The chain_code: ", inout->chain_code,sizeof(inout->chain_code));
	//Exporting the Extended private key
	memcpy(inout->Extended_private_key,I,sizeof(I));
	//Printing the Extended key copy
	printbuffer("The Extended key: ", inout->Extended_private_key,sizeof(inout->Extended_private_key));
	}

void hdnode_public_key(HDNode *node){
	//Base Point Multiplication to derive public key
	ge_p3 A;
	ge_scalarmult_base(&A, node->K_L);
    ge_p3_tobytes(node->public_key, &A);
	//Printing the Public Key
	printbuffer("The public_key: ", node->public_key,sizeof(node->public_key));
}

void hdnode_private_child_key(HDNode *inout, uint32_t i){
	uint8_t Z[28 + 4 + 32]; //buffer
	memset(Z,0,sizeof(Z));
	//Init private child key derivation
	Z_Normal_Hardened(inout->chain_code, inout->public_key, inout->Extended_private_key, Z, i);
	//Exporting Z_L & Z_R
	memset(inout->Z_L,0,sizeof(inout->Z_L));
	memcpy(inout->Z_L,Z,28);
	printbuffer("The Z_L: ", inout->Z_L,sizeof(inout->Z_L));
	memset(inout->Z_R,0,sizeof(inout->Z_R));
	memcpy(inout->Z_R,Z+32,32);
	printbuffer("The Z_R: ", inout->Z_R,sizeof(inout->Z_R));
	//Big number operations
	uint8_t zl8[32];
	uint8_t res_key[32];
	memset(zl8, 0, 32);
	/* Kl = 8*Zl + parent(K)l */
	multiply(zl8, inout->Z_L, 32);
	printbuffer("The Z_L * 8: ", zl8,sizeof(zl8));
	scalar_add(zl8, inout->K_L, res_key);
	printbuffer("The K_L: ", inout->K_L,sizeof(inout->K_L));
	memcpy(inout->K_L,res_key,32);
	printbuffer("The K_L = 8 * Z_L + K_L: ", inout->K_L,sizeof(inout->K_L));
	memset(res_key, 0, 32);
	/* Kr = Zr + parent(K)r */
	printbuffer("The Z_R: ", inout->Z_R,sizeof(inout->Z_R));
	printbuffer("The K_R: ", inout->K_R,sizeof(inout->K_R));
	add_256bits(res_key, inout->Z_R, inout->K_R);
	memcpy(inout->K_R,res_key,32);
	printbuffer("The K_R = Z_R + K_R mod 2^256: ", inout->K_R,sizeof(inout->K_R));
	memset(res_key, 0, 32);
	//Deriving child chain code
	CC_Normal_Hardened(inout->chain_code, inout->public_key, inout->Extended_private_key, inout->chain_code, i);
	//Printing the new Chain Code
	printbuffer("The chain_code: ", inout->chain_code,sizeof(inout->chain_code));		
}

void hdnode_public_child_key(HDNode *inout, uint32_t i){
	uint8_t Z[28 + 4 + 32]; //buffer
	memset(Z,0,sizeof(Z));
	//Init private child key derivation
	Z_Normal_Hardened(inout->chain_code, inout->public_key, inout->Extended_private_key, Z, i);
	//Exporting Z_L & Z_R
	memset(inout->Z_L,0,sizeof(inout->Z_L));		
	memcpy(inout->Z_L,Z,28);
	printbuffer("The Z_L: ", inout->Z_L,sizeof(inout->Z_L));
	memset(inout->Z_R,0,sizeof(inout->Z_R));
	memcpy(inout->Z_R,Z+32,32);
	printbuffer("The Z_R: ", inout->Z_R,sizeof(inout->Z_R));
	//Big number operations & point addition
	uint8_t zl8[32];
	memset(zl8, 0, 32);
	multiply(zl8, inout->Z_L, 32);
	printbuffer("The Z_L * 8: ", zl8,sizeof(zl8));
	Point_Add(inout->public_key, zl8, inout->child_public_key);		
	//Printing the child public key
	printbuffer("The child_public_key: ", inout->child_public_key,sizeof(inout->child_public_key));			
	//Deriving child chain code
	CC_Normal_Hardened(inout->chain_code, inout->public_key, inout->Extended_private_key, inout->chain_code, i);
	//Printing the new Chain Code
	printbuffer("The chain_code: ", inout->chain_code,sizeof(inout->chain_code));
}