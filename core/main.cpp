#include <iostream>
#include <string>

#include "sodium.h"

#include "data.h"
#include "constants.h"
#include "functions.h"



int main(void) {
	if (sodium_init() < 0) {
		exit(-1);
	}

	try {
		SecureCharBuffer* user;
		SecureCharBuffer* pass;

		user = new SecureCharBuffer();
		pass = new SecureCharBuffer();

	input(user);
	input(pass);

	CharBuffer key(crypto_secretbox_KEYBYTES);
	CharBuffer nonce_user(crypto_secretbox_NONCEBYTES);
	CharBuffer nonce_pass(crypto_secretbox_NONCEBYTES);

	CharBuffer encrypted_user(user->size() + crypto_secretbox_MACBYTES);
	CharBuffer encrypted_pass(pass->size() + crypto_secretbox_MACBYTES);

	crypto_secretbox_keygen(key.data());
	randombytes_buf(nonce_user.data(), nonce_user.size());
	randombytes_buf(nonce_pass.data(), nonce_pass.size());

	if (crypto_secretbox_easy(encrypted_user.data(), user->data(), user->size(), nonce_user.data(), key.data()) < 0) {
		std::cout << "error encrypting username";
	}
	if (crypto_secretbox_easy(encrypted_pass.data(), pass->data(), pass->size(), nonce_pass.data(), key.data()) < 0) {
		std::cout << "error encrypting password";
	}
	for (const auto& c : encrypted_user) std::cout << c;
	std::cout << std::endl;
	for (const auto& c : encrypted_pass) std::cout << c;
	std::cout << std::endl;

	CharBuffer decrypted(user->size());
	if (crypto_secretbox_open_easy(decrypted.data(), encrypted_user.data(), encrypted_user.size(), nonce_user.data(), key.data()) < 0) {
		std::cout << "error decrypting";
	}
	for (const auto& c : decrypted) std::cout << c;
	}
	catch (std::bad_alloc& e) {
		std::cout << e.what();
	}


	return 0;
}