# ESP8266-AES-128-CBC

This library provides a simple implementation of AES-128-CBC encryption and decryption for the ESP8266 microcontroller. It is designed to be easily compatible with Node.js, making it easy to encrypt and decrypt data across both environments.

## Features

- AES-128-CBC encryption and decryption
- PKCS7 padding
- Compatible with Node.js for cross-platform encryption and decryption

## Installation

1. Download the library and add it to your Arduino `libraries` folder.
2. Include the `AESCrypto.h` file in your project.

## Usage

### Example: ESP8266

Here's an example of how to use the `AESCrypto` library on an ESP8266:

```cpp
#include <Arduino.h>
#include "AESCrypto.h"

// Key and IV as strings (16 characters each)
String aes_key_str = "73secret!JO?&2%n";  // 16 characters
String aes_iv_str  = "vectorImmaBossYA";  // 16 characters

AESCrypto aesCrypto(aes_key_str, aes_iv_str);

void setup() {
  Serial.begin(115200);

  // Encrypting data
  String encdata = aesCrypto.encrypt("quick brown fox jumps over the lazy dog");
  Serial.println("encrypted:");  
  Serial.println(encdata);  

  // Decrypting data
  String decdata = aesCrypto.decrypt(encdata);
  Serial.println("decrypted:");  
  Serial.println(decdata);
}

void loop() {
  // No repeated tasks needed
}
```

### Example: Node.js

The following Node.js example shows how to encrypt and decrypt data in a way that's compatible with the ESP8266 library:

```javascript
const crypto        = require('crypto');

// 16-character KEY & IV
const aes_key_str   = "73secret!JO?&2%n"; 
const aes_iv_str    = "vectorImmaBossYA";

const cipher_key    = Buffer.from(aes_key_str, 'utf8');
const cipher_iv     = Buffer.from(aes_iv_str, 'utf8');

function encrypt(data){
    const   cipher      = crypto.createCipheriv('aes-128-cbc', cipher_key, cipher_iv);
    let     crypted     = cipher.update(data, 'utf-8', 'base64');
            crypted     += cipher.final('base64');
    return  crypted;
}

function decrypt(data){
    const   decipher    = crypto.createDecipheriv('aes-128-cbc', cipher_key, cipher_iv);
    let     dec         = decipher.update(data, 'base64', 'utf-8');
            dec         += decipher.final();
    return  dec;
}

// Example Usage
// let encryptedData = encrypt("quick brown fox jumps over the lazy dog");
// let decryptedData = decrypt("ue6Js6Fg0pBbwm2lF8XgLAlNeCTs58A5rfVXGqg9e6SLGZeOHzpCLt11Wiu+bPlu");
```

## License

This project is licensed under the MIT License.