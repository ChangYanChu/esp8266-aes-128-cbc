
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


#include "AESCrypto.h"

// Schlüssel und IV als String
String aes_key_str = "73secret!JO?&2%n";  // 16 Zeichen
String aes_iv_str  = "vectorImmaBossYA";  // 16 Zeichen

AESCrypto aesCrypto(aes_key_str, aes_iv_str);

void setup() {
  Serial.begin(115200);

  String encdata = aesCrypto.encrypt("quick brown fox jumps over the lazy dog");
  Serial.println("encrypted:");  
  Serial.println(encdata);  

  String decdata = aesCrypto.decrypt(encdata);
  Serial.println("decrypted:");  
  Serial.println(decdata);
}

void loop() {
  // Keine Wiederholungen nötig
}
