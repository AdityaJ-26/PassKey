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

void input( CharBuffer* data ) 
{
	std::string input;
	std::cin.ignore();
	std::getline(std::cin, input, '\n');
	
	*data = CharBuffer(input.begin(), input.end());
}

void encrypt(
	const SecureCharBuffer& user,
	const SecureCharBuffer& pass,
	const CharBuffer& key,
	const CharBuffer& metadata)
{

	CharBuffer encrypted_pass(pass.size() + crypto_secretbox_MACBYTES);
	CharBuffer encrypted_user(user.size() + crypto_secretbox_MACBYTES);
	CharBuffer nonce1(crypto_secretbox_NONCEBYTES);
	CharBuffer nonce2(crypto_secretbox_NONCEBYTES);

	randombytes_buf(nonce1.data(), sizeof(nonce1));
	if (crypto_secretbox_easy(
		encrypted_pass.data(),
		pass.data(),
		pass.size(),
		nonce1.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : error encrypting data " };
	}

	randombytes_buf(nonce2.data(), sizeof(nonce2));
	if (crypto_secretbox_easy(
		encrypted_user.data(),
		user.data(),
		user.size(),
		nonce2.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : error encrypting data " };
	}

	Data data(encrypted_pass, nonce1, encrypted_user, nonce2, metadata);
	data.store();
}


std::ostream& operator <<( std::ostream& out, const SecureCharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}

std::ostream& operator <<( std::ostream& out, const CharBuffer& data ) 
{
	for (const char& c : data) 
	{
		out << c;
	}
	out << std::endl;
	return out;
}