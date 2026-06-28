#ifndef FILES_H
#define FILES_H

#include <fstream>
#include <string>
#include <filesystem>

#include "constants.h"

const std::filesystem::path user_settings = "../data/user.bin";

struct FileHandles {
	std::fstream vault;													// bin file
	std::fstream user;													// text file
	std::filesystem::path key_path;

	FileHandles();
	~FileHandles();

	// key operations
	void openKeyFile(std::fstream&);
	void storeKeyData(const CharBuffer&, const CharBuffer&, const CharBuffer&);

	// user operations
	void createUserFile();
	void storeUserData(const std::string&, const std::string&);
	bool loadUserSettings(std::string&);
	void retrieveUserData(SecureCharBuffer&, CharBuffer&, CharBuffer&);

	template <typename T>
	void write(std::fstream&, const T&);

	template <typename T>
	bool read(std::fstream&, T&);
	
	template <typename T>
	T read(std::fstream&);

	// data operations
	void storeCredentials();
};

#endif // !FILES_H
