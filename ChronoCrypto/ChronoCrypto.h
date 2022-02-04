#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

#ifdef CHRONOCRYPTO_EXPORTS
#define CHRONOCRYPTO_API __declspec(dllexport)
#else
#define CHRONOCRYPTO_API __declspec(dllimport)
#endif


extern "C" CHRONOCRYPTO_API void blowfish_chrono(uint32_t * keybuffer, char* chrono_binary);

extern "C" CHRONOCRYPTO_API void header_magic(char* header);

extern "C" CHRONOCRYPTO_API void crypto(uint32_t * key_buffer, int should_encrypt, size_t buffer_size, uint8_t * header, uint8_t * encData);
