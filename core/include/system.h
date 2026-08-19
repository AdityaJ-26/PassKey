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
		int insert(const CharBuffer&);
		int find(const CharBuffer&) const;

	public:
		System();
		~System();

		const std::string& name() const;
		void createVaultKey(const SecureString&);
		int createNewUser(const std::string&, const std::string&);
		bool loadUser();
		void loadMetadata();
		int unlockKey(const SecureString&);
		void addEntry(const CharBuffer&, const SecureCharBuffer&, const SecureCharBuffer&);
		bool searchEntry(const CharBuffer&, SecureCharBuffer&, SecureCharBuffer&);
		void displayMetadataList() const;
		void clear();
};

# endif // ! SYSTEM_H