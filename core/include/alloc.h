/*
This is the minimal implementation of a custom allocator, all the things implemented are important for the working of allocator
*/

#ifndef ALLOC_H
#define ALLOC_H

#include <limits>
#include <memory>
#include <iostream>

#include "sodium.h"

//custom allocator class for secure memory allocation of decrypted credentials
template <typename T>
class SecureAllocator {
	public:

		SecureAllocator() = default;								// mandatory
		~SecureAllocator() = default;

		// optional aliases
		// provides standardised name for different values
		using value_type = T;										// mandatory
		using pointer = T*;
		using const_pointer = const T*;
		using reference = T&;
		using const_reference = const T&;
		using void_pointer = void*;
		using const_void_pointer = const void*;
		using size_type = size_t;
		using difference_type = std::ptrdiff_t;

		// copy constructor
		// not necessary until memory pooling or state storing
		template <typename U>
		SecureAllocator(const SecureAllocator<U>&) noexcept {}

		// allocation function
		// returns static_cast pointer of allocated memory, using sodium_malloc() to get secure memory
		// debugging not allowed with secured memory, instruction defined internally to stop execution
		pointer allocate(size_type numObjects) {					// mandatory
			pointer ptr = static_cast<pointer>(sodium_malloc(numObjects * sizeof(T)));
			if (ptr == nullptr) {
				throw std::bad_alloc();
			}
			return ptr;
		}

		// allocator for nearby/close memory allocation
		// used for faster cache perfomance
		pointer allocate(size_type numObjects, pointer hint) {
			allocate(numObjects);
		}

		// deallocation function
		// releases allocated memory using sodium_free()
		void deallocate(pointer ptr, size_type numObjects) {		// mandatory
			sodium_free(ptr);
		}

		// optional function to get max size that can be allocated
		size_type max_size() const {
			return std::numeric_limits<size_type>::max();
		}

		// equality operator, for allocator comparison, to specify move or swap operation
		friend bool operator == (const SecureAllocator&, const SecureAllocator&) noexcept { return true; }
		friend bool operator != (const SecureAllocator&, const SecureAllocator&) noexcept { return false; }
};

#endif // ALLOC_H