#ifndef __OPTIONS_H__
#define __OPTIONS_H__

// support constructing BIP32 nodes from ed25519 and curve25519 curves.
#define USE_BIP32_25519_CURVES    1

// support for printing bignum256 structures via printf
#define USE_BN_PRINT 0

// use precomputed Curve Points (some scalar multiples of curve base point G)
#ifndef USE_PRECOMPUTED_CP
#define USE_PRECOMPUTED_CP 1
#endif

// use fast inverse method
#ifndef USE_INVERSE_FAST
#define USE_INVERSE_FAST 1
#endif



// use deterministic signatures
#ifndef USE_RFC6979
#define USE_RFC6979 1
#endif

#endif
