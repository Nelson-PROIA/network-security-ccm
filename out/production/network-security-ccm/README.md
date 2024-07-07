# CCM Mode AES Encryption and Decryption

This project provides a Java implementation of Counter with CBC-MAC (CCM) mode for AES encryption and decryption. CCM mode combines Counter (CTR) mode for encryption with CBC-MAC for tag generation, supporting additional authenticated data (AAD) along with plaintext.

## Overview

The project consists of several classes:

- **CCM**: Implements AES encryption and decryption in CCM mode, including methods for encrypting plaintext, decrypting ciphertext, generating and verifying authentication tags, and formatting input for tag generation.
- **Utils**: Provides utility methods for hexadecimal string to byte array conversion and vice versa, essential for cryptographic operations.
- **Main Class (Example)**: A main class demonstrating sample usage scenarios for encrypting and decrypting data using CCM mode with AES.

## Usage

To use the CCM mode AES encryption and decryption:

1. Create an instance of the `CCM` class with a secret key represented by a `SecretKey`.
2. Use the `encryptAndGenerateTag` method to encrypt plaintext along with generating an authentication tag, and the `decryptAndVerifyTag` method to decrypt ciphertext and verify the appended authentication tag.

Example:

```java
String keyHexadecimal = "404142434445464748494A4B4C4D4E4F";
byte[] keyBytes = Utils.hexadecimalStringToByteArray(keyHexadecimal);
SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

CCM ccm = new CCM(secretKey);

String nonceHexadecimal = "10111213141516";
String associatedDataHexadecimal = "0001020304050607";
String plainTextHexadecimal = "20212223";
int tagLength = 4;

byte[] nonce = Utils.hexadecimalStringToByteArray(nonceHexadecimal);
byte[] associatedData = Utils.hexadecimalStringToByteArray(associatedDataHexadecimal);
byte[] plainText = Utils.hexadecimalStringToByteArray(plainTextHexadecimal);

byte[] cipher = ccm.encryptAndGenerateTag(nonce, associatedData, plainText, tagLength);
byte[] decrypted = ccm.decryptAndVerifyTag(nonce, associatedData, cipher, tagLength);

System.out.println("Nonce: " + Utils.byteArrayToHexadecimalString(nonce));
System.out.println("Associated data: " + Utils.byteArrayToHexadecimalString(associatedData));
System.out.println("Plain text: " + Utils.byteArrayToHexadecimalString(plainText));
System.out.println("Tag Length: " + (tagLength * 8) + " bits");
System.out.println("\nEncrypted Hexadecimal: " + Utils.byteArrayToHexadecimalString(cipher));
System.out.println("Decrypted Hexadecimal: " + Utils.byteArrayToHexadecimalString(decrypted));
```

## Contributors

- **Ricardo BOKA** - [ricardo.boka@dauphine.eu](mailto:ricardo.boka@dauphine.eu)
- **Sébastien GIRET-IMHAUS** - [sebastien.giret-imhaus@dauphine.eu](mailto:sebastien.giret-imhaus@dauphine.eu)
- **Nelson PROIA** - [nelson.proia@dauphine.eu](mailto:nelson.proia@dauphine.eu)
- **Mathieu ANDRIN** - [mathieu.andrin@dauphine.eu](mailto:mathieu.andrin@dauphine.eu)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
