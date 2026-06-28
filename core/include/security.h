#ifndef SECURITY_H
#define SECURITY_H

#include "alloc.h"
#include "files.h"

// cryptography texts generation inline functions
inline CharBuffer generateNonce();
inline SecureCharBuffer keygen();

// key decryption verification functions
bool verification(const SecureCharBuffer&, const CharBuffer&, const CharBuffer&);
bool unlock(const SecureCharBuffer&, const CharBuffer&, const CharBuffer&, SecureCharBuffer&);

// key generation/creation
void generatePassKey(const SecureCharBuffer&, const CharBuffer&);

// key encryption/decryption funcitons
SecureCharBuffer generateEncryptionKey(const CharBuffer&, const CharBuffer&);
SecureCharBuffer decryptKey(const CharBuffer&, const CharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);


#endif // !SECURITY_H