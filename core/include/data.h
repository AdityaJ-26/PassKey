#ifndef DATA_H
#define DATA_H

#include <fstream>

#include "constants.h"

class Data {
	private:
		SecureCharBuffer encrypt_password;
		SecureCharBuffer encrypt_username;
		CharBuffer password_nonce;
		CharBuffer username_nonce;
		CharBuffer metadata;
		//char passProtected;

	private:
		void encrypt(const SecureCharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);
		void decrypt( SecureCharBuffer&, SecureCharBuffer&, const SecureCharBuffer& ) const;

	public:
		Data();
		Data( const SecureCharBuffer&, const SecureCharBuffer&, const CharBuffer&, const SecureCharBuffer&);
		~Data();

		const CharBuffer& getMetaData() const;
		void getEncryptedData(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, CharBuffer&) const;
		void getData(SecureCharBuffer&, SecureCharBuffer&, const SecureCharBuffer&) const;
};

#endif // DATA_H	
