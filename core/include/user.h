#ifndef PASS_H
#define PASS_H

#include <string>

class User {
	private:
		std::string name;
	
	public:
		User();
		std::string& nameRef();
		const std::string& getName() const;
};

#endif // ! PASS_H