#ifndef SECURITY_H
#define SECURITY_H

#include "constants.h"
#include "files.h"

inline CharBuffer generateNonce();
inline SecureCharBuffer keygen();
bool unlock(FileHandles*, SecureCharBuffer&);
bool verification(FileHandles*);
void generatePassKey(const SecureCharBuffer&, const CharBuffer&);
void generateEncryptionKey(FileHandles*);
SecureCharBuffer decryptKey(const CharBuffer&, const CharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);


#endif // !SECURITY_H