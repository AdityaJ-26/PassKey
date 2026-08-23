#ifndef FILES_H
#define FILES_H

#include <fstream>
#include <string>
#include <filesystem>

#include "constants.h"

const std::filesystem::path user_settings = "data/user.bin";
const std::filesystem::path vault_path = "data/vault.bin";
const std::filesystem::path meta_path = "data/meta.bin";

class FileHandles {
	private:
		std::fstream meta;										// bin file
		std::fstream vault;										// bin file
		std::fstream user;										// text file
		std::filesystem::path key_path;

	// file read and write templates for buffers
	private:
		template <typename T>
		void write(std::fstream&, const T&);

		template <typename T>
		bool read(std::fstream&, T&);
		
		template <typename T>
		T read(std::fstream&);


	public:
		FileHandles();
		~FileHandles();
		bool verifyDirectory(const std::string&) const;	
	
		// key operations
		void createKeyFile(const std::string&);
		void openKeyFile(std::fstream&);
		void storeKeyData(const SecureCharBuffer&, const CharBuffer&, const CharBuffer&);
		void retrieveKeyData(SecureCharBuffer&, CharBuffer&, CharBuffer&);

		// user operations
		void initFiles();
		void generateUserFile();
		void storeUserData(const std::string&, const std::string&);
		int loadUserSettings(std::string&);

		// data operations

		void storeMetadata(const CharBuffer&, uint64_t, int);
		uint64_t readMetadata(CharBuffer&, int);
		uint64_t getOffset(int);
		uint64_t storeCredentials(const SecureCharBuffer&, const CharBuffer&, const SecureCharBuffer&, const CharBuffer&);
		bool retrieveCredentials(SecureCharBuffer&, CharBuffer&, SecureCharBuffer&, CharBuffer&, uint64_t);
};

#endif // !FILES_H
