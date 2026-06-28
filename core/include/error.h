#ifndef ERROR_H
#define ERROR_H


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
		const char* what() const
		{
			return this->_error.data();
		}
		
};

#endif // !ERROR_H