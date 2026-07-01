#include <iostream>

#include "data.h"
#include "error.h"
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
	const SecureCharBuffer& key)
{ 
	encrypt(pass, user, key);
}

Data::Data(
	const SecureCharBuffer& pass,
	const CharBuffer& pass_nonce,
	const SecureCharBuffer& user,
	const CharBuffer& user_nonce) :
	encrypt_password(pass), password_nonce(pass_nonce),
	encrypt_username(user), username_nonce(user_nonce)
{ }

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
// decrypt data method
/* -------------------------------------------------- */
void Data::decrypt(SecureCharBuffer& pass, SecureCharBuffer& user, const SecureCharBuffer& key) const
{
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

void Data::getEncryptedData(SecureCharBuffer& enc_pass, CharBuffer& pass_nonce, SecureCharBuffer& enc_user, CharBuffer& user_nonce) const 
{
	enc_pass = encrypt_password;
	enc_user = encrypt_username;
	pass_nonce = password_nonce;
	user_nonce = username_nonce;
}

void Data::getData(SecureCharBuffer& enc_pass, SecureCharBuffer& enc_user, const SecureCharBuffer& key) const
{
	decrypt(enc_pass, enc_user, key);
}