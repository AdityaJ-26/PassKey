#ifndef DATA_H
#define DATA_H

#include "constants.h"

class Data {
	private:
		CharBuffer encrypt_password;
		CharBuffer encrypt_username;
		CharBuffer nonce_password;
		CharBuffer nonce_username;
		CharBuffer metadata;

	public:
		Data( const CharBuffer&, const CharBuffer&, const CharBuffer&, const CharBuffer&, const CharBuffer&);
		void getData(std::vector<CharBuffer>&) const;
		const CharBuffer& getMetaData() const;
};

#endif // DATA_H
