#include "user.h"


/* -------------------------------------------------- */
// user functions
/* -------------------------------------------------- */
User::User()
{ }

const std::string& User::getName() const {
	return this->name;
}

std::string& User::nameRef() {
	return this->name;
}