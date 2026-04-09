#include <iostream>

#include "data.h"
#include "error.h"
#include "utils.h"


/* -------------------------------------------------- */
// Constructor | Destructor
/* -------------------------------------------------- */
Data::Data() :
	encrypt_password(),
	encrypt_username(),
	password_nonce(),
	username_nonce()
{ }

Data::Data( const buffer::CharBuffer& pass, 
	const buffer::CharBuffer& nonce1,
	const buffer::CharBuffer& user,
	const buffer::CharBuffer& nonce2,
	const buffer::CharBuffer& meta ) : 

	encrypt_password(pass), 
	password_nonce(nonce1),
	encrypt_username(user),
	username_nonce(nonce2),
	metadata(meta)
{ }

Data::~Data() 
{
	clear();
}


/*
zeroes the memory of data members
*/
void Data::clear()
{
	sodium_memzero(reinterpret_cast<void*>(encrypt_password.data()), encrypt_password.size());
	sodium_memzero(reinterpret_cast<void*>(encrypt_username.data()), encrypt_username.size());
	sodium_memzero(reinterpret_cast<void*>(password_nonce.data()), password_nonce.size());
	sodium_memzero(reinterpret_cast<void*>(username_nonce.data()), username_nonce.size());
}



/* -------------------------------------------------- */
// decrypt data method
/* -------------------------------------------------- */
void Data::decrypt( buffer::SecureCharBuffer& pass, buffer::SecureCharBuffer& user, const buffer::SecureCharBuffer& key ) const 
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
// store data(creds) in creds.bin
/* -------------------------------------------------- */

/*
store data in order 
	len(pass) -> pass ->
	len(pass_nonce) -> pass_nonce ->
	len(user) -> user ->
	len(user_nonce) -> user_nonce
*/
void Data::store() const 
{
	std::fstream fout;
	fout.open(filepath::DATA, std::ios::binary | std::ios::app | std::ios::out);

	if (!fout.is_open()) 
	{
		throw Error{ "_file_error : error opening file" };
	}

	size_t len{ 0 };

	len = metadata.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(metadata.data()), len);

	len = encrypt_password.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(encrypt_password.data()), len);

	len = password_nonce.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(password_nonce.data()), len);

	len = encrypt_username.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(encrypt_username.data()), len);

	len = username_nonce.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(username_nonce.data()), len);

	fout.close();
}


/* -------------------------------------------------- */
// read data(creds)
/* -------------------------------------------------- */
bool Data::read(std::fstream& fin) 
{
	size_t len{ 0 };

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		return false;
	}
	metadata.resize(len);
	fin.read(reinterpret_cast<char*>(metadata.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len))) 
	{
		throw Error{ "_file_error : file have incomplete data" };
	}
	encrypt_password.resize(len);
	fin.read(reinterpret_cast<char*>(encrypt_password.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len))) 
	{
		throw Error { "_file_error : file have incomplete data" };
	}
	password_nonce.resize(len);
	fin.read(reinterpret_cast<char*>(password_nonce.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		throw Error { "_file_error : file have incomplete data" };
	}
	encrypt_username.resize(len);
	fin.read(reinterpret_cast<char*>(encrypt_username.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		throw Error { "_file_error : file have incomplete data" };
	}
	username_nonce.resize(len);
	fin.read(reinterpret_cast<char*>(username_nonce.data()), len);

	fin.close();
	return true;
}


/* -------------------------------------------------- */
// public functions
/* -------------------------------------------------- */
const buffer::CharBuffer& Data::getMetaData() const
{
	return this->metadata;
}
