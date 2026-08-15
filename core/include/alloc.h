/*
* minimal implementation of a custom allocator for sensitive data
* uses sodium_allocarray() to allocated secure memory with overwriting and overflow corruption protection, uses sodium_mlock() to lock allocated memory0
* sodium_allocarray(count) also protect against arithmetic overflow error when count * size > INT_MAX
*/

/* MEMORY STRUCTURE
* the allocated memory is initialised with 0xdb
* structure for memory allocated using sodium_malloc(size); 
	[optional guard page]
	[canary]
	[allocated buffer]  -- data storing
	[guard page]
* guard page are inaccessible locked memory blocks, if memory overflow tries to write into guard page, program crashes from SEGFAULT/SIGSEGV.
* canary is memory block with knwown value, if overflow updates the canary value, it is checked during sodium_free() and any corruption is detected.
*/

#ifndef ALLOC_H
#define ALLOC_H

#include <limits>
#include <memory>
#include <iostream>

#include "sodium.h"

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

		// returns secure allocated memory block
		pointer allocate(size_type numObjects) {					// mandatory
			pointer ptr = static_cast<pointer>(sodium_allocarray(numObjects, sizeof(T)));
			if (ptr == nullptr) {
				throw std::bad_alloc();
			}
			return ptr;
		}

		// allocator for nearby/close memory allocation
		// used for faster cache perfomance
		pointer allocate(size_type numObjects, pointer hint) {
			return allocate(numObjects);
		}

		// sodium_free deallocates memory but before that verifies canary for any buffer overflow and terminates process if required
		void deallocate(pointer ptr, size_type numObjects) {		// mandatory
			sodium_free(ptr);
		}

		// optional function to get max size that can be allocated
		size_type max_size() const {
			return std::numeric_limits<size_type>::max() / sizeof(T);
		}

		// equality operator, for allocator comparison, to specify move or swap operation
		friend bool operator == (const SecureAllocator&, const SecureAllocator&) noexcept { return true; }
		friend bool operator != (const SecureAllocator&, const SecureAllocator&) noexcept { return false; }
};

#endif // ALLOC_H