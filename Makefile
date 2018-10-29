all: 
	g++ -O2 -std=c++11 ed25519/add_scalar.c hash/WjCryptLib_Sha512.c hash/WjCryptLib_Sha256.c hmac-sha/sha2.c ed25519/ge.c ed25519/sc.c ed25519/sha512.c ed25519/sign.c ed25519/verify.c ed25519/fe.c hmac-sha/memzero.c utils.c bip32.c test.c hmac-sha/hmac.c -o test 
	
clean:
	rm -f *.o test

run:
	./test