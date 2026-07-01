#ifndef FILES_H
#define FILES_H

#include <fstream>
#include <string>
#include <filesystem>

#include "constants.h"

const std::filesystem::path user_settings = "../data/user.bin";
const std::filesystem::path vault_path = "../data/vault.bin";
const std::filesystem::path meta_path = "../data/meta.bin";

class FileHandles {
	private:
		std::fstream meta;													// bin file
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
		bool verifyDirectory(std::string&) const;	
	
		// key operations
		void openKeyFile(std::fstream&);
		void storeKeyData(const SecureCharBuffer&, const CharBuffer&, const CharBuffer&);
		void retrieveKeyData(SecureCharBuffer&, CharBuffer&, CharBuffer&);

		// user operations
		void initUser();
		void generateUserFile();
		void storeUserData(const std::string&, const std::string&);
		bool retrieveUserSettings(std::string&);

		// data operations

		void storeMetadata(const CharBuffer&, int, int);
		int readMetadata(CharBuffer&, int);
		int getOffset(int);
		int storeCredentials(const SecureCharBuffer&, const CharBuffer&, const SecureCharBuffer&, const CharBuffer&);
		bool retrieveCredentials(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, CharBuffer&, int);
};

#endif // !FILES_H
