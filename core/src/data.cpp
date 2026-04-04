#include <iostream>

#include "data.h"
#include "error.h"
#include "utils.h"

Data::Data() :
	encrypt_password(),
	encrypt_username(),
	nonce_password(),
	nonce_username()
{ }


Data::Data( const CharBuffer& pass, 
	const CharBuffer& nonce1,
	const CharBuffer& user,
	const CharBuffer& nonce2,
	const CharBuffer& meta ) : 

	encrypt_password(pass), 
	nonce_password(nonce1),
	encrypt_username(user),
	nonce_username(nonce2),
	metadata(meta)
{ }


const CharBuffer& Data::getMetaData() const 
{
	return this->metadata;
}


void Data::decrypt( SecureCharBuffer& pass, SecureCharBuffer& user, CharBuffer& key ) const 
{
	pass.resize(encrypt_password.size());
	user.resize(encrypt_username.size());

	if (crypto_secretbox_open_easy(
		pass.data(),
		encrypt_password.data(),
		encrypt_password.size(),
		nonce_password.data(),
		key.data()) < 0)
	{
		throw Error{ "_decrypting_error : error decrypting user " };
	}

	if (crypto_secretbox_open_easy(
		user.data(),
		encrypt_username.data(),
		encrypt_username.size(),
		nonce_username.data(),
		key.data()) < 0)
	{
		throw Error{ "_decryption_error : error decrypting pass " };
	}
}


void Data::store() const 
{
	std::fstream fout;
	fout.open(FILE_PATH, std::ios::binary | std::ios::app | std::ios::out);

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

	len = nonce_password.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(nonce_password.data()), len);

	len = encrypt_username.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(encrypt_username.data()), len);

	len = nonce_username.size();
	fout.write(reinterpret_cast<const char*>(&len), sizeof(len));
	fout.write(reinterpret_cast<const char*>(nonce_username.data()), len);

	fout.close();
}


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
		return false;
	}
	encrypt_password.resize(len);
	fin.read(reinterpret_cast<char*>(encrypt_password.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len))) 
	{
		return false;
	}
	nonce_password.resize(len);
	fin.read(reinterpret_cast<char*>(nonce_password.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		return false;
	}
	encrypt_username.resize(len);
	fin.read(reinterpret_cast<char*>(encrypt_username.data()), len);

	if (!fin.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		return false;
	}
	nonce_username.resize(len);
	fin.read(reinterpret_cast<char*>(nonce_username.data()), len);

	return true;
}


void Data::clear()
{
	encrypt_password.clear();
	nonce_password.clear();
	encrypt_username.clear();
	nonce_username.clear();
}