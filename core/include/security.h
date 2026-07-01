#ifndef SECURITY_H
#define SECURITY_H

#include "files.h"

// cryptography texts generation inline functions
CharBuffer generateNonce();
SecureCharBuffer keygen();

// key decryption verification functions
bool unlock(SecureCharBuffer&, SecureString&, CharBuffer&, CharBuffer&, SecureCharBuffer&);

// key generation/creation
SecureCharBuffer generatePassKey(const SecureString&, const CharBuffer&);

// key encryption/decryption funcitons
SecureCharBuffer generateEncryptionKey(SecureString&, const CharBuffer&, const CharBuffer&);
bool decryptKey(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, SecureCharBuffer&);


#endif // !SECURITY_H