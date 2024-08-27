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
 */

#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <Arduino.h>

class AESCrypto {
  public:
    AESCrypto(String key, String iv);
    String encrypt(String plainText);
    String decrypt(String encryptedText);

  private:
    uint8_t aes_key[16];
    uint8_t aes_iv[16];

    void convertStringToHex(const String &str, uint8_t *hexArray, size_t arraySize);
    void pkcs7Padding(byte* data, size_t dataLength, size_t blockSize);
    void removePkcs7Padding(byte* data, size_t& dataLength, size_t blockSize);
};

#endif
