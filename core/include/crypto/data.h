#ifndef DATA_H
#define DATA_H

#include <fstream>

#include "constants.h"

class Data {
	private:
		buffer::CharBuffer encrypt_password;
		buffer::CharBuffer encrypt_username;
		buffer::CharBuffer password_nonce;
		buffer::CharBuffer username_nonce;
		buffer::CharBuffer metadata;

	private:
		void clear();
	
	public:
		Data();
		Data( const buffer::CharBuffer&, const buffer::CharBuffer&, const buffer::CharBuffer&, const buffer::CharBuffer&, const buffer::CharBuffer&);
		~Data();

		void store() const;
		bool read(std::fstream&);
		void decrypt( buffer::SecureCharBuffer&, buffer::SecureCharBuffer&, const buffer::SecureCharBuffer& ) const;
		const buffer::CharBuffer& getMetaData() const;
};

#endif // DATA_H
