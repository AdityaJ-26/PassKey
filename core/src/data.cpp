#include <iostream>

#include "data.h"

Data::Data( const CharBuffer& pass, 
	const CharBuffer& user,
	const CharBuffer& nonce1,
	const CharBuffer& nonce2,
	const CharBuffer& meta ) : 
	encrypt_password(pass), 
	encrypt_username(user),
	nonce_password(nonce1),
	nonce_username(nonce2),
	metadata(meta)
{ }

const CharBuffer& Data::getMetaData() const {
	return this->metadata;
}

void Data::getData(std::vector<CharBuffer>& data) const {
	data.push_back(this->encrypt_password);
	data.push_back(this->nonce_password);
	data.push_back(this->encrypt_username);
	data.push_back(this->nonce_username);
}