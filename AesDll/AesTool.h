#pragma once

#ifdef AESTOOL_EXPORTS
#define AESTOOL_API __declspec(dllexport)
#else
#define AESTOOL_API __declspec(dllimport)
#endif

extern "C" AESTOOL_API	char* encryptAndBase64(const unsigned char* plain, const unsigned char* password);

extern "C" AESTOOL_API char* uncode64AndDecrypt(const unsigned char* plain, const unsigned char* password);