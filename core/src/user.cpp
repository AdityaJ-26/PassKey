#include "user.h"


/* -------------------------------------------------- */
// user functions
/* -------------------------------------------------- */
User::User()
{ }

std::string& User::nameRef() {
	return this->name;
}