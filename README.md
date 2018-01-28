# fingerprint-auth

High level implementation steps:
1. Verify that screen lock security is enabled on device.
2. Verify that at lease one fingerprint is registered on the device.
3. Intantiate `FingerprintManager` and `Keystore`.
4. Generate encryption key and store it in the Keystore. 
5. Initialize `Cipher` instance.
6. Use `Cipher` to create a `CryptoObject`.
7. Call `FingerprintManager.authenticate()` passing `CryptoObject`.
  - Handle authentication callbacks
  - If successful, enable user access to protected content