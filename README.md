# README for Mini-Projects in Cryptography and Security

## Project 1: Mono-Alphabetic Substitution Cipher
**Objective**: Develop an encryption and decryption mechanism using a mono-alphabetic substitution of character pairs. Brute-force attacks are employed to deduce the encryption key.

### Features:
- **Encryption**: Using a table for character pair substitution, e.g., {AB -> BD, AC -> BA}.
- **Decryption**: Reversing the encryption process using the derived key.
- **Brute-force attack**: Deploying an attack to determine the encryption key, assuming the plaintext is recognizable and of sufficient length.

### Requirements:
- Input: A pair of characters, e.g., <xy>, where x, y ∈ {A, B, C}.
- Output: Encrypted and decrypted text based on the specified rules.

---

## Project 2: DES Algorithm Implementation
**Objective**: Manually implement the DES encryption and decryption algorithm focusing on each component of its 16-round process.

### Features:
- **Encryption/Decryption**: Complete manual implementation of DES without using libraries.
- **Validation**: Ensure the output after encryption is reversible and check specific rounds' equivalency:
  - Verify that the ciphertext decrypted matches the original plaintext.
  - Ensure output of the 1st encryption round matches the output of the 15th decryption round.
  - Confirm output of the 14th encryption round matches the output of the 2nd decryption round.

### Requirements:
- Input: 64-bit plaintext.
- Output: Corresponding ciphertext and validation of specific round outputs.

---

## Project 3: RSA-based Public-key Certification Authority (CA)
**Objective**: Construct a public-key certification authority that issues RSA-based public-key certificates and facilitates secure message exchanges between clients.

### Features:
- **Certificate Issuance**: Clients receive RSA-based public-key certificates.
- **Secure Communication**: Clients exchange encrypted messages using the recipient’s public key after obtaining it securely from the CA.
- **Certificate Components**: Include user ID, public key, certificate issuance time, duration, and CA ID, encrypted with the CA’s private key.

### Requirements:
- Clients already know their [private-key, public-key] pairs.
- Public key of the certification authority is known.
- Encrypted communication between clients using each other’s public keys.

---

## Project 4: Secure Time-Stamping
**Objective**: Create a system to securely timestamp documents using GMT time, ensuring document integrity and authenticity.

### Features:
- **Time-Stamping**: Documents receive a GMT timestamp and a digital signature from a dedicated server.
- **Security and Privacy**: Address the security of time retrieval and ensure that the server does not retain the original document.
- **Verification**: Provide mechanisms to verify the timestamp and document integrity using the server's public key.

### Requirements:
- Consider how and when the GMT date and time are obtained and validated.
- Implement measures to ensure document privacy and secure sharing with third parties.

### Questions to Consider:
1. How to obtain and validate GMT time securely?
2. Ensuring the server does not retain original documents.
3. Mechanisms for third parties to securely verify the document's integrity and timestamp.

---

Each project is designed to explore different aspects of cryptography and security, from basic encryption methods to complex systems involving digital signatures and public-key infrastructures.

# Copyright and License

## Copyright (c) 2024, Nikhil Suri

## All rights reserved

This code and the accompanying materials are made available on an "as is" basis, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

## No Licensing
This project is protected by copyright and other intellectual property laws. It does not come with any license that would permit reproduction, distribution, or creation of derivative works. You may not use, copy, modify, or distribute this software and its documentation without express written permission from the copyright holder.

## Contact Information
For further inquiries, you can reach me at nikhil21268@iiitd.ac.in
