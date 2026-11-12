import { hsalsa, secretbox } from "@noble/ciphers/salsa.js";
import { equalBytes, u8, u32 } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";

/** Why a key or an argument was refused, or a sealed value didn't open. */
export type SealboundErrorReason =
  | "invalid_key"
  | "key_mismatch"
  | "invalid_value"
  | "invalid_context"
  | "malformed"
  | "unknown_key"
  | "corrupt"
  | "unsupported_version"
  | "wrong_context";

export class SealboundError extends Error {
  readonly reason: SealboundErrorReason;

  constructor(
    message: string,
    reason: SealboundErrorReason,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "SealboundError";
    this.reason = reason;
  }
}

/** A sealed value, as it is stored: the box and the key that sealed it. */
export interface Sealed {
  /** A libsodium sealed box (`crypto_box_seal`). */
  ciphertext: Uint8Array;
  /** Identifies the key pair that sealed it, so keys can be rotated. */
  keyId: string;
}

/**
 * What a value belongs to: one string, or the parts of a name
 * (`["user", id, "api-token"]`). Parts are kept apart when they are hashed,
 * so `["a:b", "c"]` and `["a", "b:c"]` are two contexts.
 */
export type Context = string | readonly string[];

const BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

const BASE64_URL = /^[A-Za-z0-9_-]*$/u;
const KEY_ID = /^[0-9a-f]{16}$/u;

const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const KEY_ID_BYTES = 8;

/**
 * The checks of what a caller passes. Each takes what the types promise and
 * answers whether the promise was kept: a caller without types can pass
 * anything, and a string where bytes go would be sealed as zeros, or
 * `undefined` as a context would bind to nothing.
 */
const isText = (value: string): value is string => typeof value === "string";

const isOnePart = (value: Context): value is string =>
  typeof value === "string";

const isList = (value: readonly string[]): value is readonly string[] =>
  Array.isArray(value);

// Asked of the value's own tag, not `instanceof`: bytes made in another
// realm (an iframe, a test sandbox) are no instance of this realm's
// Uint8Array, and are bytes all the same.
const isBytes = (value: Uint8Array): value is Uint8Array =>
  Object.prototype.toString.call(value) === "[object Uint8Array]";

const isSealed = (value: Sealed): value is Sealed =>
  typeof value === "object" &&
  value !== null &&
  isBytes(value.ciphertext) &&
  isText(value.keyId) &&
  KEY_ID.test(value.keyId);

interface OpenerKeys {
  secretKey: string;
  retiredSecretKeys?: readonly string[];
}

const isOpenerKeys = (value: OpenerKeys): value is OpenerKeys =>
  typeof value === "object" &&
  value !== null &&
  isText(value.secretKey) &&
  (value.retiredSecretKeys === undefined || isList(value.retiredSecretKeys));

interface Tools {
  opener: Opener;
  sealer: Sealer;
}

const isTools = (value: Tools): value is Tools =>
  typeof value === "object" &&
  value !== null &&
  typeof value.opener === "object" &&
  value.opener !== null &&
  typeof value.sealer === "object" &&
  value.sealer !== null &&
  typeof value.opener.open === "function" &&
  typeof value.sealer.seal === "function" &&
  isText(value.opener.keyId) &&
  isText(value.sealer.keyId);

const fromBase64 = (value: string) =>
  Uint8Array.from(atob(value), (character) => character.codePointAt(0) ?? 0);

/** How many bytes become characters at once: few enough to pass as arguments. */
const CHUNK = 0x80_00;

const toBase64 = (bytes: Uint8Array) => {
  let binary = "";

  for (let start = 0; start < bytes.length; start += CHUNK) {
    binary += String.fromCodePoint(...bytes.subarray(start, start + CHUNK));
  }

  return btoa(binary);
};

const hash = (bytes: Uint8Array, length: number) =>
  blake2b(bytes, { dkLen: length });

/** A key from its text: standard base64 of exactly 32 bytes. */
const keyFrom = (value: string) => {
  const bytes =
    isText(value) && BASE64.test(value) ? fromBase64(value) : undefined;

  if (bytes?.length !== KEY_BYTES) {
    throw new SealboundError(
      "A key is not 32 bytes of standard base64",
      "invalid_key"
    );
  }

  return bytes;
};

/**
 * A public key anyone can seal to. X25519 ignores a public key's top bit and
 * reads the rest modulo the field's prime (RFC 7748, section 5), so a key
 * with that bit set, or one that isn't below the prime, is another spelling
 * of a smaller one, and would get another id. A point of low order has no shared
 * secret with anything, so nothing could ever be sealed to it.
 */
const publicKeyFrom = (value: string) => {
  const key = keyFrom(value);
  // 2^255 - 19, the field's prime, is 0xed, thirty 0xff and 0x7f as
  // little-endian bytes: a key that reads as that or more is not canonical.
  const [first = 0, ...rest] = key;
  const last = rest.pop() ?? 0;

  const canonical =
    last < 0x7f ||
    (last === 0x7f && (first < 0xed || rest.some((byte) => byte !== 0xff)));

  try {
    x25519.getSharedSecret(x25519.keygen().secretKey, key);
  } catch (error) {
    throw new SealboundError("The public key is not usable", "invalid_key", {
      cause: error,
    });
  }

  if (!canonical) {
    throw new SealboundError("The public key is not usable", "invalid_key");
  }

  return key;
};

/** A key pair's id: the first 8 bytes of its public key's BLAKE2b, in hex. */
const keyIdOf = (publicKey: Uint8Array) =>
  bytesToHex(hash(publicKey, KEY_ID_BYTES));

/** "expand 32-byte k", the Salsa20 constant, as little-endian words. */
const SIGMA = Uint32Array.of(
  0x61_70_78_65,
  0x33_20_64_6e,
  0x79_62_2d_32,
  0x6b_20_65_74
);

/**
 * NaCl's `crypto_box_beforenm`: the box key two X25519 keys share, which
 * HSalsa20 turns from the raw shared secret.
 */
const boxKey = (secretKey: Uint8Array, publicKey: Uint8Array) => {
  const shared = new Uint8Array(x25519.getSharedSecret(secretKey, publicKey));
  const key = new Uint32Array(KEY_BYTES / 4);
  hsalsa(SIGMA, u32(shared), new Uint32Array(4), key);

  return u8(key);
};

/** A sealed box's nonce, which both sides derive from the two public keys. */
const sealNonce = (ephemeral: Uint8Array, recipient: Uint8Array) =>
  hash(concatBytes(ephemeral, recipient), NONCE_BYTES);

/** libsodium's `crypto_box_seal`: the ephemeral public key, then the box. */
const sealTo = (message: Uint8Array, recipient: Uint8Array) => {
  const ephemeral = x25519.keygen();

  const box = secretbox(
    boxKey(ephemeral.secretKey, recipient),
    sealNonce(ephemeral.publicKey, recipient)
  ).seal(message);

  return concatBytes(ephemeral.publicKey, box);
};

interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** libsodium's `crypto_box_seal_open`; throws when the box is not authentic. */
const openFrom = (sealed: Uint8Array, keys: KeyPair) => {
  const ephemeral = sealed.subarray(0, KEY_BYTES);

  return secretbox(
    boxKey(keys.secretKey, ephemeral),
    sealNonce(ephemeral, keys.publicKey)
  ).open(sealed.subarray(KEY_BYTES));
};

/** The first byte of what a box holds: the version of this layout. */
const VERSION = 1;
const CONTEXT_BYTES = 32;

/** Starts every context's hash, so it is a hash nothing else computes. */
const DOMAIN = new TextEncoder().encode("sealbound/v1");
const MAX_PART_BYTES = 0xff_ff_ff_ff;

const invalidContext = (message: string) =>
  new SealboundError(message, "invalid_context");

/**
 * A context's parts as bytes. A part is a string with something in it, whose
 * every character is a real one: a lone surrogate has no UTF-8 of its own
 * and would be written as U+FFFD, the same bytes as another lone surrogate.
 */
const partsOf = (context: Context) => {
  const parts = isOnePart(context) ? [context] : context;

  if (!isList(parts) || parts.length === 0) {
    throw invalidContext("A context is a string or a list of strings");
  }

  // Array.from visits a hole in the list as `undefined`, where map skips it.
  return Array.from(parts, (part) => {
    if (!isText(part) || part === "") {
      throw invalidContext("A context's part is an empty string or no string");
    }

    if (!part.isWellFormed()) {
      throw invalidContext("A context's part has a lone surrogate");
    }

    return new TextEncoder().encode(part);
  });
};

/**
 * BLAKE2b-256 of the domain and then each part behind its length, as four
 * big-endian bytes: no two lists of parts are hashed as the same bytes.
 */
const contextDigest = (context: Context) => {
  const pieces = [DOMAIN];

  for (const part of partsOf(context)) {
    if (part.length > MAX_PART_BYTES) {
      throw invalidContext("A context's part is too long");
    }

    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, part.length);
    pieces.push(length, part);
  }

  return hash(concatBytes(...pieces), CONTEXT_BYTES);
};

/** What is sealed: the version, the context's digest and the value. */
const bind = (plaintext: Uint8Array, context: Context) => {
  const digest = contextDigest(context);

  // A string here would be written as zeros, one for each character.
  if (!isBytes(plaintext)) {
    throw new SealboundError(
      "The value to seal is not a Uint8Array",
      "invalid_value"
    );
  }

  return concatBytes(Uint8Array.of(VERSION), digest, plaintext);
};

const unbind = (framed: Uint8Array, expected: Uint8Array) => {
  if (framed.length < 1 + CONTEXT_BYTES) {
    throw new SealboundError(
      "The sealed value holds less than this library seals",
      "malformed"
    );
  }

  if (framed[0] !== VERSION) {
    throw new SealboundError(
      "The sealed value has a layout this version doesn't read",
      "unsupported_version"
    );
  }

  if (!equalBytes(framed.subarray(1, 1 + CONTEXT_BYTES), expected)) {
    throw new SealboundError(
      "The sealed value doesn't belong to this context",
      "wrong_context"
    );
  }

  return framed.slice(1 + CONTEXT_BYTES);
};

/** A stored value as it must be to be opened: its two fields, of their types. */
const checkSealed = (sealed: Sealed) => {
  if (!isSealed(sealed)) {
    throw new SealboundError(
      "A sealed value is a Uint8Array ciphertext and a key id of 16 hex digits",
      "malformed"
    );
  }

  return sealed;
};

/** A new key pair, each half as standard base64. */
export const generateKeys = () => {
  const { publicKey, secretKey } = x25519.keygen();

  return { publicKey: toBase64(publicKey), secretKey: toBase64(secretKey) };
};

/** Seals with the public key, which is all it holds: it can't open anything. */
export interface Sealer {
  keyId: string;
  seal: (plaintext: Uint8Array, context: Context) => Sealed;
}

/** Opens sealed values; whoever holds one holds the secret keys. */
export interface Opener {
  /** The current key's id; values sealed with a retired key still open. */
  keyId: string;
  open: (sealed: Sealed, context: Context) => Uint8Array;
  /** The current key's public half, for the sealers. */
  publicKey: string;
}

/**
 * A sealer for `publicKey` (base64). `seal` binds the value to `context`,
 * which names what it belongs to (`["user", id, "api-token"]`): the context
 * is sealed inside the box, and opening with another one is refused. A value
 * copied onto another owner's row therefore fails to open instead of opening
 * as that owner's.
 */
export const createSealer = (publicKey: string): Sealer => {
  const key = publicKeyFrom(publicKey);
  const keyId = keyIdOf(key);

  return {
    keyId,
    seal: (plaintext, context) => ({
      ciphertext: sealTo(bind(plaintext, context), key),
      keyId,
    }),
  };
};

const pairOf = (secretKey: string): KeyPair => {
  const secret = keyFrom(secretKey);

  return { publicKey: x25519.getPublicKey(secret), secretKey: secret };
};

/**
 * An opener holding `secretKey`, the current key, whose public half the
 * sealers use, and `retiredSecretKeys`, the earlier ones, for as long as
 * anything sealed with them remains.
 */
export const createOpener = (keys: OpenerKeys): Opener => {
  if (!isOpenerKeys(keys)) {
    throw new SealboundError(
      "An opener takes a secret key and a list of retired secret keys",
      "invalid_key"
    );
  }

  const { secretKey, retiredSecretKeys = [] } = keys;
  const current = pairOf(secretKey);
  const keyId = keyIdOf(current.publicKey);
  const keyring = new Map<string, KeyPair>([[keyId, current]]);

  for (const retired of retiredSecretKeys) {
    const pair = pairOf(retired);
    keyring.set(keyIdOf(pair.publicKey), pair);
  }

  const decrypt = ({ ciphertext, keyId: sealedWith }: Sealed) => {
    const pair = keyring.get(sealedWith);

    if (!pair) {
      throw new SealboundError(
        `Sealed with key ${sealedWith}, which this opener doesn't hold`,
        "unknown_key"
      );
    }

    try {
      return openFrom(ciphertext, pair);
    } catch (error) {
      throw new SealboundError(
        "The sealed value is corrupt or was altered",
        "corrupt",
        { cause: error }
      );
    }
  };

  return {
    keyId,
    open: (sealed, context) => {
      const digest = contextDigest(context);

      return unbind(decrypt(checkSealed(sealed)), digest);
    },
    publicKey: toBase64(current.publicKey),
  };
};

/**
 * The value to store in place of `sealed`, sealed with the current key and
 * bound to the same `context`, or null when it already is: the step of a key
 * rotation, run over every stored value. The sealer must seal with the
 * opener's current key; with any other, a rotation would look finished while
 * values stayed on a key about to be dropped, or move to one nobody can open.
 */
export const reseal = (
  tools: Tools,
  sealed: Sealed,
  context: Context
): Sealed | null => {
  if (!isTools(tools)) {
    throw new SealboundError(
      "reseal takes an opener and a sealer",
      "malformed"
    );
  }

  const { opener, sealer } = tools;

  if (sealer.keyId !== opener.keyId) {
    throw new SealboundError(
      "The sealer doesn't seal with the opener's current key",
      "key_mismatch"
    );
  }

  // Opened first in every case, so a value bound to another owner is refused.
  const plaintext = opener.open(sealed, context);

  return sealed.keyId === sealer.keyId ? null : sealer.seal(plaintext, context);
};

/** Starts a sealed value written as text; a later format gets another. */
const PREFIX = "sb1";

/**
 * A sealed value as one string, for a text column:
 * `sb1.<key id>.<ciphertext in base64url, unpadded>`.
 */
export const encode = (sealed: Sealed) => {
  const { ciphertext, keyId } = checkSealed(sealed);

  const base64Url = toBase64(ciphertext)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

  return `${PREFIX}.${keyId}.${base64Url}`;
};

/** The sealed value a string from `encode` holds. */
export const decode = (text: string): Sealed => {
  const [prefix, keyId, base64Url, ...rest] = isText(text)
    ? text.split(".")
    : [];

  if (
    prefix !== PREFIX ||
    keyId === undefined ||
    !KEY_ID.test(keyId) ||
    base64Url === undefined ||
    !BASE64_URL.test(base64Url) ||
    // Unpadded base64 never leaves one character over.
    base64Url.length % 4 === 1 ||
    rest.length > 0
  ) {
    throw new SealboundError(
      "The text is not a sealed value written by encode",
      "malformed"
    );
  }

  const base64 = base64Url.replaceAll("-", "+").replaceAll("_", "/");

  const sealed = {
    ciphertext: fromBase64(
      base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")
    ),
    keyId,
  };

  // Base64 ignores the bits its last character has to spare, so several
  // texts would read as the same value: only the one encode writes is taken.
  if (encode(sealed) !== text) {
    throw new SealboundError(
      "The text is not a sealed value written by encode",
      "malformed"
    );
  }

  return sealed;
};
