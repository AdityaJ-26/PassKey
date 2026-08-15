#ifndef CLI_H
#define CLI_H

#include "system.h"

class CLI {
	private:
		System* system;
		bool loggedIn;

	public:
		bool running;

	public:
		CLI();
		~CLI();

		void printHelpMenu() const;
		void printCLI() const;
		void printHeader() const;
		void printSoftwareInfo() const;
		void processInput(const std::string&);
};

# endif // ! CLI_H