#include "security.h"
#include "error.h"
#include "utils.h"

/* -------------------------------------------------- */
// repeated generation functions
/* -------------------------------------------------- */
CharBuffer generateNonce()
{
	CharBuffer nonce(crypto_secretbox_NONCEBYTES);
	randombytes_buf(nonce.data(), crypto_secretbox_NONCEBYTES);
	return nonce;
}

SecureCharBuffer keygen()
{
	SecureCharBuffer key(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.data());
	return key;
}


/* -------------------------------------------------- */
// key unlock function
/* -------------------------------------------------- */
/*
* prompt for master password and decrypts the encryption_key
*/
bool unlock(SecureCharBuffer& encrypted_key, SecureString& password, CharBuffer& salt, CharBuffer& nonce, SecureCharBuffer& encryption_key)
{
	SecureCharBuffer pass_key = generatePassKey(password, salt);
	zero(password);
	zero(salt);

	encryption_key.resize(encrypted_key.size() - crypto_secretbox_MACBYTES);
	return decryptKey(pass_key, nonce, encrypted_key, encryption_key);
}


/* -------------------------------------------------- */
// key_derivation(password, salt)
/* -------------------------------------------------- */
/*
* generate a encryption_key from password and salt
* OPSLIMIT and MEMLIMIT are resources limiting factors, uses more CPU cycles (increasing CPU use) and more memory (increased RAM USAGE)
* MODERATE variant requires 256 MiB of dedicated RAM and takes about 0.7 seconds on a 2.8 GHz Core i7 CPU [libsodium docs].
*/
SecureCharBuffer generatePassKey(const SecureString& password, const CharBuffer& salt)
{
	SecureCharBuffer pass_key(crypto_secretbox_KEYBYTES);

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
// keygen and encryption
/* -------------------------------------------------- */
/*
* generates a random encryption key
* uses passkey generated from master password, and encrypts the encryption key
*/
SecureCharBuffer generateEncryptionKey(SecureString& password, const CharBuffer& salt, const CharBuffer& nonce) 
{
	SecureCharBuffer pass_key = generatePassKey(password, salt);

	zero(password);

	SecureCharBuffer encryption_key = keygen();
	SecureCharBuffer encrypted_key(crypto_secretbox_MACBYTES + encryption_key.size());
		
	{
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
	zero(encryption_key);
	return encrypted_key;
}


/* -------------------------------------------------- */
// encryption_key decryption
/* -------------------------------------------------- */
bool decryptKey(SecureCharBuffer& pass_key, CharBuffer& nonce, SecureCharBuffer& enc_key, SecureCharBuffer& encrytion_key) 
{
	SecureCharBuffer encryption_key(enc_key.size() - crypto_secretbox_MACBYTES);
	if (crypto_secretbox_open_easy(
		encryption_key.data(),
		enc_key.data(),
		enc_key.size(),
		nonce.data(),
		pass_key.data()) != 0)
	{
		zero(enc_key);
		zero(pass_key);
		zero(nonce);
		return false;
	}
	zero(enc_key);
	zero(nonce);
	zero(enc_key);
	return true;
}


