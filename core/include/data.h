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
		char passProtected;

		void encrypt(const SecureCharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);

	public:
		Data();
		Data( const SecureCharBuffer&, const SecureCharBuffer&, const CharBuffer&, const SecureCharBuffer&, char );
		~Data();

		void store(std::fstream&) const;
		bool retrieve(std::fstream&, const int&);
		void decrypt( SecureCharBuffer&, SecureCharBuffer&, const SecureCharBuffer& ) const;
		const CharBuffer& getMetaData() const;
};

#endif // DATA_H	
