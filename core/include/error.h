#ifndef ERROR_H
#define ERROR_H

#include <string>


/* -------------------------------------------------- */
// exception error class
/* -------------------------------------------------- */
class Error {
	private:
		std::string _error;

	public:
		Error( std::string err = "_unexpected_error" ) :
			_error(err)
		{ }
		const std::string& what() 
			{ return this->_error; }
		
};

#endif // !ERROR_H