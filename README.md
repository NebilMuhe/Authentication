# Authentication
This project provides an implementation of authentication mechanisms using **JWT** (JSON Web Tokens) and **PASETO** (Platform-Agnostic Security Tokens). It includes both symmetric and asymmetric cryptographic methods for token generation and verification.

## Features

- **JWT Implementation**:
  - Both Symmetric and Asymmetric signing.
  - Token creation with claims like `Subject`, `Issuer`, `Audience`, and expiration times.
  - Token verification to ensure validity and integrity.

- **PASETO Implementation**:
  - Symmetric Signing using secret key and Asymmetric signing using `ed25519` keys.
  - Secure token creation with footer and audience support.
  - Token verification using the public key.

- **Unit Tests**:
  - Comprehensive tests for both JWT and PASETO implementations.
  - Validation of token creation and verification processes.
