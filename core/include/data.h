#ifndef DATA_H
#define DATA_H

#include <fstream>

#include "constants.h"

class Data {
	private:
		CharBuffer encrypt_password;
		CharBuffer encrypt_username;
		CharBuffer nonce_password;
		CharBuffer nonce_username;
		CharBuffer metadata;

	public:
		Data();
		Data( const CharBuffer&, const CharBuffer&, const CharBuffer&, const CharBuffer&, const CharBuffer&);
		const CharBuffer& getMetaData() const;
		void store() const;
		void decrypt( SecureCharBuffer&, SecureCharBuffer&, CharBuffer& ) const;
		bool read(std::fstream&);
		void clear();
};

#endif // DATA_H
