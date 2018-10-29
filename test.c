/*Code Amir Hossein Alikhah Mishamandani, 2018, MIT licence */
/*  Distributed for free and with no warranty  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "bip32.h"
#include "ed25519/ed25519.h"
int checkendianness(){
    volatile uint32_t i=0x01234567;
    // return 0 for big endian, 1 for little endian.
    return (*((uint8_t*)(&i))) == 0x67;
}

void test1(){
	
	//test the node init func
	printf("Initiating the HDnode from the seed ...\n");
	HDNode node;
	Init_hdnode("ddab3114c720ec2e7b30536ad30583ea248e6642bc774ea463822430ec3c5a7b", &node);
	//hdnode_public_key(&node);
	hdnode_public_key(&node);
	//testing the initialized __Pk__ & __SK__
	unsigned char signature[64];
	const unsigned char message[] = "TEST MESSAGE";
	/* create signature on the message with the key pair */
	ed25519_sign(signature, message, sizeof(message), &node);
	/* verify the signature */
	if (ed25519_verify(signature, message, sizeof(message), node.public_key)) {
		printf("\nvalid signature ...!\n\n");
	} else {
		printf("\nError: invalid signature ...!\n\n");
	}
	printf("Deriving the child private key m/0' ...\n");
	//Deriving the first private child key
	hdnode_private_child_key(&node, 0);
	//The Child Public Key of the Child Private key
	//hdnode_public_key(&node);
	hdnode_public_key(&node);
	/* create signature on the message with the key pair */
	memset(signature,0,sizeof(signature));
	ed25519_sign(signature, message, sizeof(message), &node);
	/* verify the signature */
	if (ed25519_verify(signature, message, sizeof(message), node.public_key)) {
		printf("\nvalid signature ...!\n\n");
	} else {
		printf("\nError: invalid signature ...!\n\n");
	}
	
	
	
	//test the node init func
	printf("Initiating the HDnode from the seed ...\n");
	HDNode node1;
	Init_hdnode("ddab3114c720ec2e7b30536ad30583ea248e6642bc774ea463822430ec3c5a7b", &node1);
	//hdnode_public_key(&node);
	hdnode_public_key(&node1);
	/* create signature on the message with the key pair */
	ed25519_sign(signature, message, sizeof(message), &node1);
	/* verify the signature */
	if (ed25519_verify(signature, message, sizeof(message), node1.public_key)) {
		printf("\nvalid signature ...!\n\n");
	} else {
		printf("\nError: invalid signature ...!\n\n");
	}	
	printf("Deriving the child public key m/0' ...\n");
	//Deriving the first public child key
	hdnode_public_child_key(&node1, 0);
	/* create signature on the message with the key pair */
	memset(signature,0,sizeof(signature));
	ed25519_sign(signature, message, sizeof(message), &node1);
	/* verify the signature */
	if (ed25519_verify(signature, message, sizeof(message), node1.public_key)) {
		printf("\nvalid signature ...!\n\n");
	} else {
		printf("\nError: invalid signature ...!\n\n");
	}	
}

int main(){
	
	system("clear");
	
	test1();
	
}


