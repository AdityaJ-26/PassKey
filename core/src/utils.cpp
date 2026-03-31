#include <iostream>
#include <string>

#include "error.h"
#include "utils.h"

void init()
{
	if (sodium_init() < 0)
	{
		throw Error{ "_lib_error : error initialising libsodium" };
	}
}

void input( SecureCharBuffer* user )
{
	SecureString input;
	std::getline(std::cin, input, '\n');

	*user = SecureCharBuffer(input.begin(), input.end());
}

void input( CharBuffer* data ) {
	std::string input;
	std::cin.ignore();
	std::getline(std::cin, input, '\n');
	
	*data = CharBuffer(input.begin(), input.end());
}

void encrypt(
	const SecureCharBuffer& user,
	const SecureCharBuffer& pass,
	std::vector<Data>& passwords,
	const CharBuffer& key,
	const CharBuffer& metadata)
{

	CharBuffer encrypted_pass(pass.size() + crypto_secretbox_MACBYTES);
	CharBuffer encrypted_user(user.size() + crypto_secretbox_MACBYTES);
	CharBuffer nonce1(crypto_secretbox_NONCEBYTES);
	CharBuffer nonce2(crypto_secretbox_NONCEBYTES);

	randombytes_buf(nonce1.data(), sizeof(nonce1));
	if (crypto_secretbox_easy(encrypted_user.data(),
		user.data(),
		user.size(),
		nonce1.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : error encrypting data " };
	}

	randombytes_buf(nonce2.data(), sizeof(nonce2));
	if (crypto_secretbox_easy(encrypted_pass.data(),
		pass.data(),
		pass.size(),
		nonce2.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : error encrypting data " };
	}


	Data data(encrypted_pass, encrypted_user, nonce2, nonce1, metadata);
	passwords.push_back(data);
}

void decrypt(const Data& data, SecureCharBuffer& user, SecureCharBuffer& pass, CharBuffer& key) {
	std::vector<CharBuffer> creds;
	data.getData(creds);

	//user.reserve(crypto_secretbox_MACBYTES + creds[1].size());
	//pass.reserve(crypto_secretbox_MACBYTES + creds[0].size());

	CharBuffer temp_pass(creds[0].size() + crypto_secretbox_MACBYTES);
	CharBuffer temp_user(creds[2].size() + crypto_secretbox_MACBYTES);

	if (crypto_secretbox_open(
		temp_pass.data(),
		creds[0].data(),
		creds[0].size(),
		creds[1].data(),
		key.data()) < 0)
	{
		throw Error{ "_decrypting_error : error decrypting data " };
	}
	if (crypto_secretbox_open(
		temp_user.data(),
		creds[2].data(),
		creds[2].size(),
		creds[3].data(),
		key.data()) < 0)
	{
		throw Error{ "_decryption_error : error decrypting data " };
	}
	std::cout << temp_pass << std::endl << temp_user << std::endl;
}


std::ostream& operator <<( std::ostream& out, const SecureCharBuffer& data ) {
	for (const char& c : data) {
		out << c;
	}
	out << std::endl;
	return out;
}

std::ostream& operator <<( std::ostream& out, const CharBuffer& data ) {
	for (const char& c : data) {
		out << c;
	}
	out << std::endl;
	return out;
}