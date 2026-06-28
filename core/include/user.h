#ifndef PASS_H
#define PASS_H

#include <string>

#include "constants.h"
#include "files.h"

class User {
	private:
		std::string name;
	
	public:
		User();
		std::string& nameRef();
		const std::string& getName() const;
};

#endif // ! PASS_H