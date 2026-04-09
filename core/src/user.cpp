#include <fstream>

#include "sodium.h"

#include "user.h"
#include "constants.h"
#include "error.h"
#include "functions.h"
#include "utils.h"


/* -------------------------------------------------- */
// Password data storing
/* -------------------------------------------------- */

/*
stores the salt used to derive key from password, nonce for master key decryption, and encryption_key
order size(salt) -> salt ->
	  size(nonce) -> nonce ->
	  size(enc_key) -> key
*/
void store(const buffer::CharBuffer& key, const buffer::CharBuffer& salt, const buffer::CharBuffer& nonce) 
{
	std::fstream file;
	file.open(filepath::KEY, std::ios::binary | std::ios::out);
	if (!file.is_open())
	{
		throw Error{ "_file_error : failed to open key file" };
	}

	size_t len{ 0 };
	len = salt.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(salt.data()), len);

	len = nonce.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(nonce.data()), len);

	len = key.size();
	file.write(reinterpret_cast<const char*>(&len), sizeof(len));
	file.write(reinterpret_cast<const char*>(key.data()), len);

	file.close();
}

/* -------------------------------------------------- */
// key_derivation(password, salt)
/* -------------------------------------------------- */
buffer::SecureCharBuffer generatePassKey(const buffer::SecureString& password, const buffer::CharBuffer& salt) 
{
	buffer::SecureCharBuffer pass_key(crypto_secretbox_KEYBYTES);

	if (crypto_pwhash(
		pass_key.data(),
		pass_key.size(),
		password.data(),
		password.size(),
		salt.data(),
		crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT) != 0)
	{
		throw Error{ "_keygen_error : error deriving key from password " };
	}

	return pass_key;
}

/* -------------------------------------------------- */
// Password input and pass_key generation
/* -------------------------------------------------- */

/*
inputs password and generate pass_key, store authentication phrase and store key data
*/
void initUser()
{
	init();
	buffer::SecureString password;
	std::cout << "Enter Password: ";
	std::cin >> password;

	buffer::CharBuffer salt(crypto_pwhash_SALTBYTES);
	randombytes_buf(salt.data(), salt.size());

	buffer::SecureCharBuffer pass_key = generatePassKey(password, salt);

	sodium_memzero(password.data(), password.size());

	buffer::SecureCharBuffer encryption_key(crypto_secretbox_KEYBYTES);
	buffer::CharBuffer nonce = generateNonce();
	buffer::CharBuffer encrypted_key(encryption_key.size() + crypto_secretbox_MACBYTES);
	
	{

		crypto_secretbox_keygen(encryption_key.data());
		if (crypto_secretbox_easy(
			encrypted_key.data(),
			encryption_key.data(),
			encryption_key.size(),
			nonce.data(),
			pass_key.data()) != 0)
		{
			throw Error{ "_encrypt_error : failed to encrypt key" };
		}
	}
	
	store(encrypted_key, salt, nonce);

	sodium_memzero(encrypted_key.data(), encrypted_key.size());	
	sodium_memzero(salt.data(), salt.size());	
	sodium_memzero(nonce.data(), nonce.size());	
}


/* -------------------------------------------------- */
// reads Key, salt, nonce
/* -------------------------------------------------- */
void retrieve(buffer::SecureCharBuffer& key, buffer::CharBuffer& salt, buffer::CharBuffer& nonce)
{
	std::fstream file;
	file.open(filepath::KEY, std::ios::binary | std::ios::in);
	if (!file.is_open())
	{
		throw Error { "_file_error : failed to access key file" };
	}

	size_t len{ 0 };
	
	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		throw Error { "_file_error : failed to read data" };
	}
	file.read(reinterpret_cast<char*>(salt.data()), len);

	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		throw Error{ "_file_error : corrupted file" };
	}
	file.read(reinterpret_cast<char*>(nonce.data()), len);

	if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)))
	{
		throw Error{ "_file_error : corrupted file" };
	}
	key.resize(len);
	file.read(reinterpret_cast<char*>(key.data()), len);
}



/* -------------------------------------------------- */
// Encryption key access
/* -------------------------------------------------- */

/*
decrypts encryption_key using password
*/
buffer::SecureCharBuffer loadUser()
{
	buffer::CharBuffer salt(crypto_pwhash_SALTBYTES);
	buffer::CharBuffer nonce(crypto_secretbox_NONCEBYTES);
	buffer::SecureCharBuffer encrypted_key;

	retrieve(encrypted_key, salt, nonce);

	buffer::SecureString password;
	std::cout << "Enter password : ";
	std::cin >> password;

	buffer::SecureCharBuffer pass_key = generatePassKey(password, salt);
	
	buffer::SecureCharBuffer key(encrypted_key.size() - crypto_secretbox_MACBYTES);

	if (crypto_secretbox_open_easy(
		key.data(),
		encrypted_key.data(),
		encrypted_key.size(),
		nonce.data(),
		pass_key.data()) != 0)
	{
		throw Error{ "_decryption_error : failed to decrypt key" };
	}

	return key;
}