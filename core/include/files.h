#ifndef FILES_H
#define FILES_H

#include <fstream>
#include <string>
#include <filesystem>

#include "constants.h"

const std::filesystem::path user_settings = "../data/user.bin";

class FileHandles {
	private:
		std::fstream vault;													// bin file
		std::fstream user;													// text file
		std::filesystem::path key_path;

	private:
		// read and write template for Buffers
		template <typename T>
		void write(std::fstream&, const T&);

		template <typename T>
		bool read(std::fstream&, T&);
		
		template <typename T>
		T read(std::fstream&);

	public:
		FileHandles();
		~FileHandles();

	
		// key operations
		void openKeyFile(std::fstream&);
		void storeKeyData(const CharBuffer&, const CharBuffer&, const CharBuffer&);
		void retrieveKeyData(SecureCharBuffer&, CharBuffer&, CharBuffer&);

		// user operations
		void createUserFile();
		void storeUserData(const std::string&, const std::string&);
		bool loadUserSettings(std::string&);

		// data operations
		void storeCredentials(const SecureCharBuffer&, const CharBuffer&, const SecureCharBuffer&, const CharBuffer&);
		bool retrieveCredentials(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, CharBuffer&, char&, int);
};

#endif // !FILES_H
