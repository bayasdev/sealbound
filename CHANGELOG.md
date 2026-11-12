# Changelog

## 1.0.3

The first release after 1.0.1: 1.0.2 was tagged and never reached npm, because the new publish workflow failed at its last step.

- The publish workflow runs the toolchain, publishes and creates the release in three jobs, each with only the permission it needs, and every action is pinned to a commit.
- `reseal` opens the value the sealer made with the opener's current key and compares it with the original before returning it. 1.0.1 read the key id on that value, which a sealer of your own could set to the current key while sealing with another, or for another context. A value `reseal` returns now always opens with the current key.

## 1.0.1

Fixes from a security review. The format is the same, and what 1.0.0 sealed on a little-endian machine, which is nearly every machine, still opens.

- `reseal` checks the value the sealer made, not the key id the sealer reports, so a sealer of your own or one that was changed can't leave values on a retired key. Sealers and openers are now frozen.
- A context with tens of thousands of parts no longer overflows the stack.
- An object that only names itself a `Uint8Array` is refused as a value and as a ciphertext.
- A key written in another base64 spelling of the same bytes is refused, as `decode` already did for sealed values.
- The box key is derived correctly on big-endian machines, where 1.0.0 would not have matched libsodium.
- Contexts no longer need `String.prototype.isWellFormed`, so older browsers work.
- The README says the key id is BLAKE2b with an 8-byte digest, not the first 8 bytes of a longer one, and that values sealed for the same context can be swapped for each other.

## 1.0.0

First version.

- `createSealer` seals a value with a public key and binds it to a context, the name of what it belongs to, given as one string or a list of parts.
- `createOpener` opens sealed values with the secret key, and with retired keys while values sealed with them remain.
- `reseal` moves a value onto the current key, for key rotation.
- `encode` and `decode` write a sealed value as one string and read it back.
- `generateKeys` makes a key pair.
