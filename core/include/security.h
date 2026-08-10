#ifndef SECURITY_H
#define SECURITY_H

#include "files.h"

// cryptography texts generation inline functions
CharBuffer generateNonce();
inline SecureCharBuffer keygen();

SecureCharBuffer derivePasswordKey(const SecureString&, const CharBuffer&);

// key generation/creation
SecureCharBuffer generateVaultKey(const SecureString&, const CharBuffer&, const CharBuffer&);

// key decryption verification function
bool decryptVaultKey(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, SecureCharBuffer&);
bool unlockVaultKey(SecureCharBuffer&, const SecureString&, CharBuffer&, CharBuffer&, SecureCharBuffer&);



#endif // !SECURITY_H