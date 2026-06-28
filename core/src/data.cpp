#include <iostream>

#include "data.h"
#include "error.h"
#include "utils.h"
#include "security.h"


/* -------------------------------------------------- */
// Constructor | Destructor
/* -------------------------------------------------- */
Data::Data() :
	encrypt_password(),
	encrypt_username(),
	password_nonce(),
	username_nonce()
{ }

Data::Data(
	const SecureCharBuffer& pass, 
	const SecureCharBuffer& user, 
	const CharBuffer& metadata,
	const SecureCharBuffer& key, 
	char passProtect) :
	metadata{metadata},
	passProtected{passProtected}
{ 
	encrypt(pass, user, key);
}

/*
* zeroes the memory of data members
* using sodium_memzero, CharBuffer do not zeroes memory by default
*/
Data::~Data() 
{
	sodium_memzero(reinterpret_cast<void*>(encrypt_password.data()), encrypt_password.size());
	sodium_memzero(reinterpret_cast<void*>(encrypt_username.data()), encrypt_username.size());
	sodium_memzero(reinterpret_cast<void*>(password_nonce.data()), password_nonce.size());
	sodium_memzero(reinterpret_cast<void*>(username_nonce.data()), username_nonce.size());
}


/* -------------------------------------------------- */
// encrypt method()
/* -------------------------------------------------- */

/*
* encrypts credentials
*/
void Data::encrypt(const SecureCharBuffer& user, const SecureCharBuffer& pass, const SecureCharBuffer& key)
{
	encrypt_password.resize(pass.size() + crypto_secretbox_MACBYTES);
	encrypt_username.resize(user.size() + crypto_secretbox_MACBYTES);
	username_nonce = generateNonce();
	password_nonce = generateNonce();

	if (crypto_secretbox_easy(
		encrypt_password.data(),
		pass.data(),
		pass.size(),
		password_nonce.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : failed to encrypt data " };
	}

	if (crypto_secretbox_easy(
		encrypt_username.data(),
		user.data(),
		user.size(),
		username_nonce.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : faild to encrypt data " };
	}
}


/* -------------------------------------------------- */
// store data(creds) in creds.bin
/* -------------------------------------------------- */

/*
* store data in order 
	len(metadata) -> metadata ->
	len(pass) -> pass ->
	len(pass_nonce) -> pass_nonce ->
	len(user) -> user ->
	len(user_nonce) -> user_nonce
*/
void Data::store(std::fstream& vault) const 
{
	vault.seekp(0, std::ios::end);
	write(vault, encrypt_password);
	write(vault, password_nonce);
	write(vault, encrypt_username);
	write(vault, username_nonce);
	write(vault, passProtected);

	// for padding of data to use with metadata indexing
	uint64_t data_size
	{
		encrypt_password.size() +
		encrypt_username.size() +
		(crypto_secretbox_NONCEBYTES * 2) +
		(4 * 8) + 1
	};
	CharBuffer padding;
	randombytes(padding.data(), PADDING_SIZE - data_size);
	write(vault, padding);
}


/* -------------------------------------------------- */
// read data(creds)
/* -------------------------------------------------- */
bool Data::retrieve(std::fstream& vault, const int& offset) 
{
	vault.seekg(offset * PADDING_SIZE, std::ios::beg); // move to indexed data
	// change this so that metadata returns false and otherwise error is thrown when not able to read something in utils::read
	return 
		read(vault, encrypt_password) &&
		read(vault, password_nonce) &&
		read(vault, encrypt_username) &&
		read(vault, username_nonce) &&
		read(vault, passProtected);
}


/* -------------------------------------------------- */
// decrypt data method
/* -------------------------------------------------- */
void Data::decrypt(SecureCharBuffer& pass, SecureCharBuffer& user, const SecureCharBuffer& key) const
{
	if (passProtected == 'y') 
	{
		bool result = verification();
		if (result == false) 
		{
			std::cout << "Wrong password : ";
			return;
		}
	}
	pass.resize(encrypt_password.size() - crypto_secretbox_MACBYTES);
	user.resize(encrypt_username.size() - crypto_secretbox_MACBYTES);

	if (crypto_secretbox_open_easy(
		pass.data(),
		encrypt_password.data(),
		encrypt_password.size(),
		password_nonce.data(),
		key.data()) < 0)
	{
		throw Error{ "_decrypting_error : error decrypting user " };
	}

	if (crypto_secretbox_open_easy(
		user.data(),
		encrypt_username.data(),
		encrypt_username.size(),
		username_nonce.data(),
		key.data()) < 0)
	{
		throw Error{ "_decryption_error : error decrypting pass " };
	}
}


/* -------------------------------------------------- */
// public functions
/* -------------------------------------------------- */
const CharBuffer& Data::getMetaData() const
{
	return this->metadata;
}