#include "security.h"
#include "error.h"
#include "utils.h"

/* -------------------------------------------------- */
// repeated generation functions
/* -------------------------------------------------- */
CharBuffer generateNonce() {
	CharBuffer nonce(crypto_secretbox_NONCEBYTES);
	randombytes_buf(nonce.data(), crypto_secretbox_NONCEBYTES);
	return nonce;
}

inline SecureCharBuffer keygen() {
	SecureCharBuffer key(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.data());
	return key;
}


/* -------------------------------------------------- */
// key_derivation(password, salt)
/* -------------------------------------------------- */
/*
* generate a encryption_key from master_password and salt
* OPSLIMIT and MEMLIMIT are resources limiting factors, uses more CPU cycles (increasing CPU use) and more memory (increased RAM USAGE)
* MODERATE variant requires 256 MiB of dedicated RAM and takes about 0.7 seconds on a 2.8 GHz Core i7 CPU [libsodium docs].
*/
SecureCharBuffer derivePasswordKey(const SecureString& password, const CharBuffer& salt) {
	SecureCharBuffer password_derived_key(crypto_secretbox_KEYBYTES);
	if (crypto_pwhash(
		password_derived_key.data(),
		password_derived_key.size(),
		password.data(),
		password.size(),
		salt.data(),
		crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT) != 0)
	{
		throw Error{ "_keygen_error : error deriving key from password " };
	}
	return password_derived_key;
}


/* -------------------------------------------------- */
// keygen and encryption
/* -------------------------------------------------- */
/*
* generates a random vault_key and encrypts using crypto_secretbox_easy()
* key for encryption of vault_key is generated using HKDF from master_password
* returns the encrypted vault_key
*/
SecureCharBuffer generateVaultKey(const SecureString& password, const CharBuffer& salt, const CharBuffer& nonce)  {
	SecureCharBuffer password_derived_key = derivePasswordKey(password, salt);

	SecureCharBuffer encryption_key = keygen();
	SecureCharBuffer encrypted_key(crypto_secretbox_MACBYTES + encryption_key.size());
	{
		if (crypto_secretbox_easy(
			encrypted_key.data(),
			encryption_key.data(),
			encryption_key.size(),
			nonce.data(),
			password_derived_key.data()) != 0)
		{
			throw Error{ "_encrypt_error : failed to encrypt key" };
		}
	}

	zero(encryption_key);
	return encrypted_key;
}


/* -------------------------------------------------- */
// vault_key decryption
/* -------------------------------------------------- */
bool decryptVaultKey(SecureCharBuffer& password_derived_key, CharBuffer& nonce, SecureCharBuffer& enc_key, SecureCharBuffer& encrytion_key)  {
	SecureCharBuffer encryption_key(enc_key.size() - crypto_secretbox_MACBYTES);
	if (crypto_secretbox_open_easy(
		encryption_key.data(),
		enc_key.data(),
		enc_key.size(),
		nonce.data(),
		password_derived_key.data()) != 0)
	{
		zero(enc_key);
		zero(password_derived_key);
		zero(nonce);
		return false;
	}
	zero(enc_key);
	zero(nonce);
	zero(enc_key);
	return true;
}


/* -------------------------------------------------- */
// vault_key unlock function
/* -------------------------------------------------- */
/*
* unlocks the encrypted_vault_key using password_derived_key and returns success return code (boolean)
*/
bool unlockVaultKey(SecureCharBuffer& encrypted_key, const SecureString& password, CharBuffer& salt, CharBuffer& nonce, SecureCharBuffer& encryption_key) {
	SecureCharBuffer password_derived_key = derivePasswordKey(password, salt);
	zero(salt);

	encryption_key.resize(encrypted_key.size() - crypto_secretbox_MACBYTES);
	return decryptVaultKey(password_derived_key, nonce, encrypted_key, encryption_key);
}