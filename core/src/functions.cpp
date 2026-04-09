#include "sodium.h"

#include "functions.h"

buffer::CharBuffer generateNonce() {
	buffer::CharBuffer nonce(crypto_secretbox_NONCEBYTES);
	randombytes_buf(nonce.data(), nonce.size());
	return nonce;
}