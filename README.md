# Tamper Proof Data

At Bequest, we require that important user data is tamper proof. Otherwise, our system can incorrectly distribute assets if our internal server or database is breached. 

**1. How does the client ensure that their data has not been tampered with?**

- The client ensures that their data has not been tampered with by using encryption and integrity checks
- The encryptData function in the server code is responsible for encrypting the sensitive data before storing it.
  - It uses the crypto library to create a cipher with the AES-256-CBC algorithm.
  - The data is encrypted using the specified encryption key and an initialization vector (IV).
  - The IV is then prepended to the encrypted data and sent to the server.

- The decryptData function in the server code is responsible for decrypting the data before sending it to the client.
  - It extracts the IV from the encrypted data, creates a decipher with the same algorithm and key, and then decrypts the data.
  - The decrypted data is then sent to the client.

- Secure the Apis:
  - HTTPS (SSL/TLS Encryption)
    - The server is configured to use HTTPS to encrypt data during transmission.
    - SSL/TLS certificates (private key and certificate) are loaded from the specified files (.env variables PRIVATE_KEY and CERTIFICATE).
  - CORS (Cross-Origin Resource Sharing).
    - The server is configured to allow requests only from specified origins in the whitelist array.
  - JWT (JSON Web Token) Authentication.
    - The verifyJWT middleware ensures that incoming requests have a valid JWT in the Authorization header.
  - Rate Limiting.
    - This helps prevent abuse and protects against certain types of attacks.

<br />

**2. If the data has been tampered with, how can the client recover the lost data?**

- A backup function (saveBackup) is created to save a backup of the user data whenever it is updated through the api endpoint.
- The backup data is saved in a JSON file (data_backup.json) in the same directory for now. This can be saved on secure place like S3.
- An endpoint (/restore) is created to handle the restoration of the backup.


Edit this repo to answer these two questions using any technologies you'd like, there any many possible solutions. Feel free to add comments.

### To run the apps:
```npm run start``` in both the frontend and backend

## To make a submission:
1. Clone the repo
2. Make a PR with your changes in your repo
3. Email your github repository to robert@bequest.finance
