#ifndef SYSTEM_H
#define SYSTEM_H

#include "files.h"
#include "user.h"

class System 
{
	private:
		FileHandles* sys_files;
		User* user;
		SecureCharBuffer vault_key;
		std::vector<CharBuffer> meta_list;

	private:
		void loadMetadata();
		int insert(CharBuffer&);
		int find(const CharBuffer&) const;
		void createKey();

	public:
		System();
		~System();

		void loadUser();
		void createNewUser();
		void unlockKey();
		void newEntry();
		void displayEntry();
		void displayMetaList() const;
};

# endif // ! SYSTEM_H