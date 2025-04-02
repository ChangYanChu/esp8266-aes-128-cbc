/*
 * ESP8266-AES-128-CBC
 *
 * This library provides simple AES-128-CBC encryption and decryption functionality
 * for Arduino projects. It allows you to securely encrypt and decrypt strings
 * using a 16-character key and initialization vector (IV).
 *
 * Compatible with the ESP8266 platform and integrates with BearSSL for cryptographic operations.
 *
 * Author: cooper.bin @ makesmart.net
 * Version: 1.0.0
 * License: MIT
 *
 * Example usage:
 *
 *   #include "AESCrypto.h"
 *
 *   AESCrypto aesCrypto("16-char-key!", "16-char-iv!!");
 *
 *   String encrypted = aesCrypto.encrypt("your message here");
 *   String decrypted = aesCrypto.decrypt(encrypted);
 *
 * This library is also compatible with Node.js using the following structure:
 *
 *   const crypto = require('crypto');
 *   const key    = Buffer.from('16-char-key!', 'utf8');
 *   const iv     = Buffer.from('16-char-iv!!', 'utf8');
 *   const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
 *   // Encryption and Decryption...
 *
 *  Thanks to https://github.com/kakopappa/esp8266-aes-cbc-encryption-decryption
 *
 */

 #include "AESCrypto.h"

 #if defined(ESP8266)
 #include <bearssl/bearssl.h>
 #elif defined(ESP32)
 #include "mbedtls/aes.h"
 #endif
 
 #include "Base64.h"
 
 AESCrypto::AESCrypto(String key, String iv)
 {
   convertStringToHex(key, aes_key, sizeof(aes_key));
   convertStringToHex(iv, aes_iv, sizeof(aes_iv));
 }
 
 void AESCrypto::convertStringToHex(const String &str, uint8_t *hexArray, size_t arraySize)
 {
   for (size_t i = 0; i < arraySize; ++i)
   {
     hexArray[i] = str[i];
   }
 }
 
 String AESCrypto::encrypt(String plainText)
 {
   int len = plainText.length();
   int n_blocks = len / 16 + 1;
   uint8_t data[n_blocks * 16];
   memcpy(data, plainText.c_str(), len);
   pkcs7Padding(data, len, 16);
 
   uint8_t key[16], iv[16];
   memcpy(key, aes_key, 16);
   memcpy(iv, aes_iv, 16);
 
 #if defined(ESP8266)
   // BearSSL
   br_aes_big_cbcenc_keys encCtx;
   br_aes_big_cbcenc_init(&encCtx, key, 16);
   br_aes_big_cbcenc_run(&encCtx, iv, data, n_blocks * 16);
 #elif defined(ESP32)
   // mbedTLS
   mbedtls_aes_context encCtx;
   mbedtls_aes_init(&encCtx);
   mbedtls_aes_setkey_enc(&encCtx, key, 128);
   mbedtls_aes_crypt_cbc(&encCtx, MBEDTLS_AES_ENCRYPT, n_blocks * 16, iv, data, data);
   mbedtls_aes_free(&encCtx);
 #endif
 
   len = n_blocks * 16;
   char encoded_data[base64_enc_len(len)];
   base64_encode(encoded_data, (char *)data, len);
   return String(encoded_data);
 }
 
 String AESCrypto::decrypt(String encryptedText)
 {
   int input_len = encryptedText.length();
   char *encoded_data = const_cast<char *>(encryptedText.c_str());
   int len = base64_dec_len(encoded_data, input_len);
   uint8_t data[len];
   base64_decode((char *)data, encoded_data, input_len);
 
   uint8_t key[16], iv[16];
   memcpy(key, aes_key, 16);
   memcpy(iv, aes_iv, 16);
 
   int n_blocks = len / 16;
 
 #if defined(ESP8266)
   // BearSSL
   br_aes_big_cbcdec_keys decCtx;
   br_aes_big_cbcdec_init(&decCtx, key, 16);
   br_aes_big_cbcdec_run(&decCtx, iv, data, n_blocks * 16);
 #elif defined(ESP32)
   // mbedTLS
   mbedtls_aes_context decCtx;
   mbedtls_aes_init(&decCtx);
   mbedtls_aes_setkey_dec(&decCtx, key, 128);
   mbedtls_aes_crypt_cbc(&decCtx, MBEDTLS_AES_DECRYPT, n_blocks * 16, iv, data, data);
   mbedtls_aes_free(&decCtx);
 #endif
 
   size_t dataLen = len;
   removePkcs7Padding(data, dataLen, 16);
   return String((char *)data).substring(0, dataLen);
 }
 
 void AESCrypto::pkcs7Padding(byte *data, size_t dataLength, size_t blockSize)
 {
   size_t paddingLen = blockSize - (dataLength % blockSize);
   for (size_t i = dataLength; i < dataLength + paddingLen; i++)
   {
     data[i] = paddingLen;
   }
 }
 
 void AESCrypto::removePkcs7Padding(byte *data, size_t &dataLength, size_t blockSize)
 {
   size_t paddingLen = data[dataLength - 1];
   if (paddingLen <= blockSize)
   {
     dataLength -= paddingLen;
   }
 }