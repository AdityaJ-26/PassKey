#include "encrypt.h"
#include "error.h"
#include "data.h"
#include "functions.h"


/* -------------------------------------------------- */
// encrypt method()
/* -------------------------------------------------- */
void encrypt(
	const buffer::SecureCharBuffer& user,
	const buffer::SecureCharBuffer& pass,
	const buffer::SecureCharBuffer& key,
	const buffer::CharBuffer& metadata)
{

	buffer::CharBuffer encrypted_pass(pass.size() + crypto_secretbox_MACBYTES);
	buffer::CharBuffer encrypted_user(user.size() + crypto_secretbox_MACBYTES);
	buffer::CharBuffer nonce1 = generateNonce();
	buffer::CharBuffer nonce2 = generateNonce();

	if (crypto_secretbox_easy(
		encrypted_pass.data(),
		pass.data(),
		pass.size(),
		nonce1.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : failed to encrypt data " };
	}

	if (crypto_secretbox_easy(
		encrypted_user.data(),
		user.data(),
		user.size(),
		nonce2.data(),
		key.data()) < 0)
	{
		throw Error{ "_encrypt_error : faild to encrypt data " };
	}
	

	// Data object created and stored
	Data data(encrypted_pass, nonce1, encrypted_user, nonce2, metadata);
	data.store();
}
