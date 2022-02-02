#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

#ifdef CHRONOCRYPTO_EXPORTS
#define CHRONOCRYPTO_API __declspec(dllexport)
#else
#define CHRONOCRYPTO_API __declspec(dllimport)
#endif


extern "C" CHRONOCRYPTO_API void blowfish(uint32_t * keybuffer, char* blowfish_s_init, char* blowfish_p_init, char* blowfish_key);

extern "C" CHRONOCRYPTO_API void header_magic(char* header);

extern "C" CHRONOCRYPTO_API void crypto(uint32_t * key_buffer, int should_encrypt, size_t buffer_size, uint8_t * header, uint8_t * encData);
