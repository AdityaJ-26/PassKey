#ifndef SYSTEM_H
#define SYSTEM_H

#include "files.h"
#include "user.h"

class System {
	private:
		FileHandles* sys_files;
		User* user;
		SecureCharBuffer vault_key;
		std::vector<CharBuffer> metadata_list;

	private:
		int insert(CharBuffer&);
		int find(const CharBuffer&) const;
		void createVaultKey();
		void loadMetadata();

	public:
		System();
		~System();

		void createNewUser();
		void loadUser();
		bool unlockKey();
		void addEntry();
		void searchEntry();
		void displayMetadataList() const;
		void exit();
};

# endif // ! SYSTEM_H