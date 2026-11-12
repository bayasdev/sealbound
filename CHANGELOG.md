# Changelog

## 1.0.0

First version.

- `createSealer` seals a value with a public key and binds it to a context, the name of what it belongs to, given as one string or a list of parts.
- `createOpener` opens sealed values with the secret key, and with retired keys while values sealed with them remain.
- `reseal` moves a value onto the current key, for key rotation.
- `encode` and `decode` write a sealed value as one string and read it back.
- `generateKeys` makes a key pair.
