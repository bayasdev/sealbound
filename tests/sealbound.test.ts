import vm from "node:vm";
import * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";
import sodium, { ready, to_hex } from "libsodium-wrappers";
import { describe, expect, it } from "vitest";
import {
  createOpener,
  createSealer,
  decode,
  encode,
  generateKeys,
  reseal,
  SealboundError,
} from "../src/index.ts";
import type { Context, Sealed } from "../src/index.ts";

await ready;

const keys = generateKeys();
const other = generateKeys();
const sealer = createSealer(keys.publicKey);
const opener = createOpener({ secretKey: keys.secretKey });
const CONTEXT = ["user", "a", "api-token"];
const encoder = new TextEncoder();

/** The reason a call is refused for, or null when it isn't. */
const refusal = (call: () => object | string) => {
  try {
    call();
  } catch (error) {
    if (error instanceof SealboundError) {
      return error.reason;
    }

    throw error;
  }

  return null;
};

/**
 * These let a test pass any value where the types ask for another, as a
 * caller without types does: each claims the value is what the library takes,
 * and checks nothing, which is the library's to do.
 */
const asContext = (_value: unknown): _value is Context => true;
const asBytes = (_value: unknown): _value is Uint8Array => true;
const asSealed = (_value: unknown): _value is Sealed => true;
const asText = (_value: unknown): _value is string => true;

const asKeys = (
  _value: unknown
): _value is Parameters<typeof createOpener>[0] => true;

const asTools = (_value: unknown): _value is Parameters<typeof reseal>[0] =>
  true;

const drawParts = (tc: hegel.TestCase) =>
  Array.from(
    { length: tc.draw(gs.integers({ maxValue: 4, minValue: 1 })) },
    () => tc.draw(gs.text({ maxSize: 20, minSize: 1 }))
  );

/**
 * The format, computed by libsodium alone: the digest of a context, and what
 * a box holds for it.
 */
const partBytes = (part: string) => {
  const bytes = encoder.encode(part);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.length);

  return [...length, ...bytes];
};

const digestOf = (context: Context) =>
  sodium.crypto_generichash(
    32,
    Uint8Array.from([
      ...encoder.encode("sealbound/v1"),
      ...[context].flat().flatMap(partBytes),
    ]),
    null
  );

const framed = (plaintext: Uint8Array, context: Context, version = 1) =>
  Uint8Array.from([version, ...digestOf(context), ...plaintext]);

describe("a sealed value", () => {
  it("whatever is sealed opens back to the same bytes, for any context", () => {
    hegel.test((tc) => {
      const plaintext = new Uint8Array(tc.draw(gs.binary({ maxSize: 4096 })));
      const context = drawParts(tc);
      expect(
        opener.open(sealer.seal(plaintext, context), context)
      ).toStrictEqual(plaintext);
    });
  });

  it("refuses a one-byte change anywhere in the ciphertext", () => {
    hegel.test(
      (tc) => {
        const plaintext = new Uint8Array(tc.draw(gs.binary({ maxSize: 2048 })));
        const sealed = sealer.seal(plaintext, CONTEXT);

        const index = tc.draw(
          gs.integers({ maxValue: sealed.ciphertext.length - 1, minValue: 0 })
        );

        const altered = new Uint8Array(sealed.ciphertext);
        altered[index] = ((altered[index] ?? 0) + 1) % 256;
        expect(
          refusal(() =>
            opener.open({ ...sealed, ciphertext: altered }, CONTEXT)
          )
        ).toBe("corrupt");
      },
      { testCases: 128 }
    );
  });

  it("the ciphertext doesn't contain the plaintext", () => {
    const secret = encoder.encode("the-secret-nobody-should-read");
    const { ciphertext } = sealer.seal(secret, CONTEXT);
    // Latin-1 maps each byte to one character, so a substring is a byte run.
    expect(Buffer.from(ciphertext).toString("latin1")).not.toContain(
      Buffer.from(secret).toString("latin1")
    );
  });

  it("another key pair can't open it, even when the value is relabelled as its own", () => {
    const stranger = createOpener({ secretKey: other.secretKey });
    const sealed = sealer.seal(new Uint8Array([1, 2, 3]), CONTEXT);
    expect(refusal(() => stranger.open(sealed, CONTEXT))).toBe("unknown_key");
    expect(
      refusal(() =>
        stranger.open({ ...sealed, keyId: stranger.keyId }, CONTEXT)
      )
    ).toBe("corrupt");
  });

  it("relabelled as a retired key the opener also holds, it still doesn't open", () => {
    // The nonce is made from the recipient's public key, so the label can't
    // point a value at another key.
    const both = createOpener({
      retiredSecretKeys: [other.secretKey],
      secretKey: keys.secretKey,
    });

    const theirs = createSealer(other.publicKey);
    const sealed = sealer.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(() => both.open({ ...sealed, keyId: theirs.keyId }, CONTEXT))
    ).toBe("corrupt");
  });

  it("opens values of every key it holds, and only those", () => {
    const retired = generateKeys();

    const box = createSealer(retired.publicKey).seal(
      new Uint8Array([7, 7]),
      CONTEXT
    );

    const rotated = createOpener({
      retiredSecretKeys: [retired.secretKey],
      secretKey: keys.secretKey,
    });

    expect(rotated.open(box, CONTEXT)).toStrictEqual(new Uint8Array([7, 7]));
    expect(
      rotated.open(sealer.seal(new Uint8Array([8]), CONTEXT), CONTEXT)
    ).toStrictEqual(new Uint8Array([8]));
    expect(refusal(() => opener.open(box, CONTEXT))).toBe("unknown_key");
  });

  it("an opener gives the public key its sealers need", () => {
    expect(opener.publicKey).toBe(keys.publicKey);
    expect(opener.keyId).toBe(sealer.keyId);
  });
});

describe("the context", () => {
  it("a value moved to another context is refused, whatever the two are", () => {
    hegel.test((tc) => {
      // A database writer copies one owner's sealed value onto another's row.
      const plaintext = new Uint8Array(tc.draw(gs.binary({ maxSize: 512 })));
      const owner = drawParts(tc);
      const elsewhere = drawParts(tc);
      tc.assume(JSON.stringify(owner) !== JSON.stringify(elsewhere));
      const sealed = sealer.seal(plaintext, owner);
      expect(refusal(() => opener.open(sealed, elsewhere))).toBe(
        "wrong_context"
      );
    });
  });

  it("parts are kept apart: the same characters split elsewhere are another context", () => {
    hegel.test((tc) => {
      const left = tc.draw(gs.text({ maxSize: 10, minSize: 1 }));
      const right = tc.draw(gs.text({ maxSize: 10, minSize: 2 }));
      const sealed = sealer.seal(new Uint8Array([1]), [left, right]);
      // One character moves from the second part to the first.
      const [moved = ""] = right;
      expect(
        refusal(() =>
          opener.open(sealed, [`${left}${moved}`, right.slice(moved.length)])
        )
      ).toBe("wrong_context");
      expect(refusal(() => opener.open(sealed, [`${left}:${right}`]))).toBe(
        "wrong_context"
      );
    });
  });

  it("one string is the context of that one part", () => {
    const sealed = sealer.seal(new Uint8Array([5]), "user:42");
    expect(opener.open(sealed, ["user:42"])).toStrictEqual(new Uint8Array([5]));
  });

  it.each([
    ["an empty string", ""],
    ["an empty list", []],
    ["a list with an empty part", ["user", ""]],
    ["undefined, as a missing id gives", undefined],
    ["null", null],
    ["a number", 42],
    ["a list with a part that isn't a string", ["user", 42]],
    // TextEncoder writes any lone surrogate as U+FFFD, so two of them would
    // be one context.
    ["a lone surrogate", "user:\uD800"],
  ])("%s is refused, to seal and to open", (_, context) => {
    const sealed = sealer.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(() =>
        asContext(context) ? sealer.seal(new Uint8Array([1]), context) : {}
      )
    ).toBe("invalid_context");
    expect(
      refusal(() => (asContext(context) ? opener.open(sealed, context) : {}))
    ).toBe("invalid_context");
  });
});

describe("what is refused before anything is sealed or opened", () => {
  it.each([
    ["a string, which would be sealed as zeros", "hello"],
    ["an ArrayBuffer", new ArrayBuffer(4)],
    ["an array of numbers", [1, 2, 3]],
    ["nothing", undefined],
  ])("a value that is %s", (_, value) => {
    expect(
      refusal(() => (asBytes(value) ? sealer.seal(value, CONTEXT) : {}))
    ).toBe("invalid_value");
  });

  it("a key that isn't 32 bytes of standard base64", () => {
    hegel.test((tc) => {
      const bytes = tc.draw(gs.binary({ maxSize: 64 }));
      tc.assume(bytes.length !== 32);
      const key = Buffer.from(bytes).toString("base64");
      expect(refusal(() => createSealer(key))).toBe("invalid_key");
      expect(refusal(() => createOpener({ secretKey: key }))).toBe(
        "invalid_key"
      );
    });
    // base64url, which standard base64 isn't.
    expect(
      refusal(() =>
        createSealer(
          Buffer.from(keys.publicKey, "base64").toString("base64url")
        )
      )
    ).toBe("invalid_key");
  });

  it("a public key nothing can be sealed to: the point of order one", () => {
    // All zeros is a point of low order (RFC 7748, section 6.1).
    expect(
      refusal(() => createSealer(Buffer.alloc(32).toString("base64")))
    ).toBe("invalid_key");
  });

  it("a public key with its top bit set, another spelling of the same key", () => {
    const bytes = Buffer.from(keys.publicKey, "base64");
    // X25519 masks the top bit of the last byte (RFC 7748, section 5).
    bytes[31] = (bytes[31] ?? 0) + 0x80;
    expect(refusal(() => createSealer(bytes.toString("base64")))).toBe(
      "invalid_key"
    );
  });

  it.each([
    ["nothing", null],
    [
      "a ciphertext as a string, as a text column returns it",
      { ciphertext: "AAAA", keyId: sealer.keyId },
    ],
    [
      "a ciphertext as an array of numbers",
      { ciphertext: [1, 2], keyId: sealer.keyId },
    ],
    [
      "a key id that isn't 16 hex digits",
      {
        ciphertext: new Uint8Array(80),
        keyId: `${sealer.keyId}\nforged log line`,
      },
    ],
  ])("a sealed value that is %s", (_, sealed) => {
    expect(
      refusal(() => (asSealed(sealed) ? opener.open(sealed, CONTEXT) : {}))
    ).toBe("malformed");
  });
});

/**
 * libsodium is the oracle for the format: what it seals must open here, and
 * what is sealed here must open there.
 */
describe("compatibility with libsodium's sealed boxes", () => {
  const publicKey = Buffer.from(keys.publicKey, "base64");
  const secretKey = Buffer.from(keys.secretKey, "base64");

  it("a generated key pair is a libsodium key pair, with the key id libsodium computes", () => {
    expect(sodium.crypto_scalarmult_base(secretKey)).toStrictEqual(
      new Uint8Array(publicKey)
    );
    expect(sealer.keyId).toBe(
      to_hex(sodium.crypto_generichash(8, publicKey, null))
    );
  });

  it("opens what libsodium sealed", () => {
    hegel.test((tc) => {
      const plaintext = new Uint8Array(tc.draw(gs.binary({ maxSize: 1024 })));
      const context = drawParts(tc);

      const ciphertext = sodium.crypto_box_seal(
        framed(plaintext, context),
        publicKey
      );

      expect(
        opener.open({ ciphertext, keyId: opener.keyId }, context)
      ).toStrictEqual(plaintext);
    });
  });

  it("is opened by libsodium", () => {
    hegel.test((tc) => {
      const plaintext = new Uint8Array(tc.draw(gs.binary({ maxSize: 1024 })));
      const context = drawParts(tc);
      const { ciphertext } = sealer.seal(plaintext, context);
      expect(
        sodium.crypto_box_seal_open(ciphertext, publicKey, secretKey)
      ).toStrictEqual(framed(plaintext, context));
    });
  });

  it("refuses a box whose layout has another version, sealed for the same context", () => {
    hegel.test((tc) => {
      const version = tc.draw(gs.integers({ maxValue: 255, minValue: 0 }));
      tc.assume(version !== 1);

      const ciphertext = sodium.crypto_box_seal(
        framed(new Uint8Array([9]), CONTEXT, version),
        publicKey
      );

      expect(
        refusal(() => opener.open({ ciphertext, keyId: opener.keyId }, CONTEXT))
      ).toBe("unsupported_version");
    });
  });

  it("opens a value sealed by libsodium 0.8.4 on 2026-11-12, as every later version must", () => {
    // The key pair is libsodium's crypto_box_seed_keypair of the bytes 0 to
    // 31, and the box its crypto_box_seal of 0x01, the digest of
    // ["user", "42", "api-token"] and the text below.
    const frozen = createOpener({
      secretKey: "PZTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8=",
    });

    const sealed = decode(
      "sb1.ddf8df3f8ebe4091.oB0OU52zEzjsI-iRS8_kr0YgHlleCymYmpRM9Fq6fHaJic_V89vT9BPuW5T--wOqnj3Gwi-Ts_3zFdK130JBwquHnJvoV9RAcqkB3NKk6h0JW6joEO2JTT14ed-CqBVjd5cGcEo3T_hl4HzCTA"
    );

    expect(frozen.publicKey).toBe(
      "RwHQhIhFH1RaQJ+1iuPlhYHKQKw/fxFGmM1x3qxzygE="
    );
    expect(
      new TextDecoder().decode(frozen.open(sealed, ["user", "42", "api-token"]))
    ).toBe("correct horse battery staple");
  });
});

describe("re-sealing", () => {
  const retired = generateKeys();

  const rotated = createOpener({
    retiredSecretKeys: [retired.secretKey],
    secretKey: keys.secretKey,
  });

  const old = createSealer(retired.publicKey);

  it("moves a value of a retired key to the current one, readable by the new opener alone", () => {
    const box = old.seal(new Uint8Array([1, 2]), CONTEXT);
    const moved = reseal({ opener: rotated, sealer }, box, CONTEXT);
    expect(moved?.keyId).toBe(sealer.keyId);
    expect(opener.open(moved ?? box, CONTEXT)).toStrictEqual(
      new Uint8Array([1, 2])
    );
  });

  it("leaves a value that is already on the current key", () => {
    const box = sealer.seal(new Uint8Array([1]), CONTEXT);
    expect(reseal({ opener, sealer }, box, CONTEXT)).toBeNull();
  });

  it("refuses to re-seal a value that belongs to another context", () => {
    const theirs = sealer.seal(new Uint8Array([1]), ["user", "b", "api-token"]);
    expect(
      refusal(() => reseal({ opener, sealer }, theirs, CONTEXT) ?? {})
    ).toBe("wrong_context");
  });

  it("refuses a sealer still on the old key, which would call every old value current", () => {
    const box = old.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(
        () => reseal({ opener: rotated, sealer: old }, box, CONTEXT) ?? {}
      )
    ).toBe("key_mismatch");
  });

  it("refuses a sealer for a key the opener doesn't hold, which nothing could open again", () => {
    const box = sealer.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(
        () =>
          reseal(
            { opener, sealer: createSealer(other.publicKey) },
            box,
            CONTEXT
          ) ?? {}
      )
    ).toBe("key_mismatch");
  });
});

describe("a sealed value as text", () => {
  it("comes back from its text as it was", () => {
    hegel.test((tc) => {
      const sealed = sealer.seal(
        new Uint8Array(tc.draw(gs.binary({ maxSize: 2048 }))),
        CONTEXT
      );

      const text = encode(sealed);
      expect(decode(text)).toStrictEqual(sealed);
      // The prefix, the key id and unpadded base64url, between dots.
      expect(text).toMatch(/^sb1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+$/u);
    });
  });

  it("is the ciphertext in base64url, as Node writes it", () => {
    hegel.test((tc) => {
      const sealed = sealer.seal(
        new Uint8Array(tc.draw(gs.binary({ maxSize: 512 }))),
        CONTEXT
      );

      expect(encode(sealed)).toBe(
        `sb1.${sealed.keyId}.${Buffer.from(sealed.ciphertext).toString("base64url")}`
      );
    });
  });

  it.each([
    ["another prefix", "sb2.0123456789abcdef.AAAA"],
    ["no key id", "sb1..AAAA"],
    ["a key id in capitals", "sb1.0123456789ABCDEF.AAAA"],
    ["standard base64, with its padding", "sb1.0123456789abcdef.AA=="],
    ["a length base64 never has", "sb1.0123456789abcdef.AAAAA"],
    ["a fourth part", "sb1.0123456789abcdef.AAAA.AAAA"],
    ["not a string", 42],
  ])("text with %s is refused", (_, text) => {
    expect(refusal(() => (asText(text) ? decode(text) : {}))).toBe("malformed");
  });
});

describe("what the second review found", () => {
  it("text that isn't the one encode writes is refused, though base64 would read it", () => {
    hegel.test((tc) => {
      // The box adds 81 bytes (a 32-byte key, a 16-byte tag, the version and
      // the 32-byte digest), so the ciphertext is one byte over a multiple of
      // three, which leaves the last character four spare bits (RFC 4648,
      // section 3.5).
      const sealed = sealer.seal(
        new Uint8Array(
          3 * tc.draw(gs.integers({ maxValue: 40, minValue: 0 })) + 1
        ),
        CONTEXT
      );

      const text = encode(sealed);
      const last = text.at(-1) ?? "";

      const ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

      const spelling = tc.draw(gs.integers({ maxValue: 15, minValue: 1 }));

      // Another character with the same top two bits.
      const respelled = ALPHABET.charAt(
        Math.floor(ALPHABET.indexOf(last) / 16) * 16 +
          ((ALPHABET.indexOf(last) + spelling) % 16)
      );

      expect(sealed.ciphertext.length % 3).toBe(1);
      expect(refusal(() => decode(`${text.slice(0, -1)}${respelled}`))).toBe(
        "malformed"
      );
    });
  });

  it("a value longer than one chunk is written as Node writes it", () => {
    hegel.test(
      (tc) => {
        // encode turns bytes into characters 32,768 at a time.
        const size = tc.draw(
          gs.integers({ maxValue: 100_000, minValue: 32_769 })
        );

        const sealed = sealer.seal(new Uint8Array(size).fill(7), CONTEXT);
        expect(encode(sealed)).toBe(
          `sb1.${sealed.keyId}.${Buffer.from(sealed.ciphertext).toString("base64url")}`
        );
        expect(opener.open(decode(encode(sealed)), CONTEXT)).toHaveLength(size);
      },
      { testCases: 10 }
    );
  });

  it.each([
    ["a ciphertext as a string", { ciphertext: "AAAA", keyId: sealer.keyId }],
    ["nothing", null],
  ])("encode refuses %s", (_, sealed) => {
    expect(refusal(() => (asSealed(sealed) ? encode(sealed) : {}))).toBe(
      "malformed"
    );
  });

  it("bytes made in another realm are bytes", () => {
    const foreign: unknown = vm.runInNewContext("new Uint8Array([1, 2, 3])");
    expect(foreign instanceof Uint8Array).toBeFalsy();
    const sealed = asBytes(foreign) ? sealer.seal(foreign, CONTEXT) : null;
    expect(sealed && opener.open(sealed, CONTEXT)).toStrictEqual(
      new Uint8Array([1, 2, 3])
    );
  });

  it("a public key that isn't below the field's prime, another spelling of a smaller one", () => {
    hegel.test((tc) => {
      // 2^255 - 19 is 0xed, thirty 0xff and 0x7f, little-endian (RFC 7748,
      // section 4.1). The offsets 2 to 18 spell the numbers 2 to 18 again.
      const offset = tc.draw(gs.integers({ maxValue: 18, minValue: 2 }));
      const bytes = Buffer.alloc(32, 0xff);
      bytes[0] = 0xed + offset;
      bytes[31] = 0x7f;
      expect(refusal(() => createSealer(bytes.toString("base64")))).toBe(
        "invalid_key"
      );
    });
  });

  it.each([
    ["nothing", undefined],
    ["null", null],
    [
      "retired keys that aren't a list",
      { retiredSecretKeys: 5, secretKey: keys.secretKey },
    ],
    [
      "retired keys as one string",
      { retiredSecretKeys: keys.secretKey, secretKey: keys.secretKey },
    ],
    ["no secret key", {}],
  ])("an opener made from %s is refused", (_, options) => {
    expect(refusal(() => (asKeys(options) ? createOpener(options) : {}))).toBe(
      "invalid_key"
    );
  });

  it.each([
    ["nothing", null],
    ["an opener and a sealer that aren't", { opener: {}, sealer: {} }],
    ["no sealer", { opener }],
  ])("reseal with %s for its tools is refused", (_, tools) => {
    const sealed = sealer.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(() =>
        asTools(tools) ? (reseal(tools, sealed, CONTEXT) ?? {}) : {}
      )
    ).toBe("malformed");
  });

  it.each([
    // A list of three with nothing in its second place.
    [
      "a hole in its list",
      Object.assign(Array.from<string>({ length: 0 }), {
        0: "user",
        2: "api-token",
      }),
    ],
  ])("a context with %s is refused", (_, context) => {
    expect(
      refusal(() =>
        asContext(context) ? sealer.seal(new Uint8Array([1]), context) : {}
      )
    ).toBe("invalid_context");
  });

  it("a box that holds less than a version and a digest is no sealed value of this library", () => {
    hegel.test((tc) => {
      // 1 byte of version and 32 of digest come before any value.
      const short = new Uint8Array(tc.draw(gs.binary({ maxSize: 32 })));

      const ciphertext = sodium.crypto_box_seal(
        short,
        Buffer.from(keys.publicKey, "base64")
      );

      expect(
        refusal(() => opener.open({ ciphertext, keyId: opener.keyId }, CONTEXT))
      ).toBe("malformed");
    });
  });
});

describe("what the third review found", () => {
  it("reseal checks what the sealer made, whatever the sealer says its key is", () => {
    const retired = generateKeys();

    const rotated = createOpener({
      retiredSecretKeys: [retired.secretKey],
      secretKey: keys.secretKey,
    });

    const old = createSealer(retired.publicKey);
    // A sealer of the caller's own, which names the current key and seals
    // with the retired one.
    const lying = { keyId: rotated.keyId, seal: old.seal };
    const box = old.seal(new Uint8Array([1]), CONTEXT);
    expect(
      refusal(
        () => reseal({ opener: rotated, sealer: lying }, box, CONTEXT) ?? {}
      )
    ).toBe("key_mismatch");
  });

  it("reseal opens what the sealer made: a sealer that relabels its output, seals for another context or seals another value is refused", () => {
    const retired = generateKeys();

    const rotated = createOpener({
      retiredSecretKeys: [retired.secretKey],
      secretKey: keys.secretKey,
    });

    const old = createSealer(retired.publicKey);
    const box = old.seal(new Uint8Array([1]), CONTEXT);

    const relabelling = {
      keyId: rotated.keyId,
      seal: (plaintext: Uint8Array, context: Context) => ({
        ...old.seal(plaintext, context),
        keyId: rotated.keyId,
      }),
    };

    const elsewhere = {
      keyId: rotated.keyId,
      seal: (plaintext: Uint8Array) => sealer.seal(plaintext, "elsewhere"),
    };

    const swapping = {
      keyId: rotated.keyId,
      seal: (_plaintext: Uint8Array, context: Context) =>
        sealer.seal(new Uint8Array([2]), context),
    };

    expect(
      [relabelling, elsewhere, swapping].map((custom) =>
        refusal(
          () => reseal({ opener: rotated, sealer: custom }, box, CONTEXT) ?? {}
        )
      )
    ).toStrictEqual(["key_mismatch", "key_mismatch", "key_mismatch"]);
  });

  it("a sealer and an opener can't be changed after they are made", () => {
    expect([Object.isFrozen(sealer), Object.isFrozen(opener)]).toStrictEqual([
      true,
      true,
    ]);
  });

  it("a context of more parts than a function takes arguments is sealed and opened like any other", () => {
    // 70,000 parts overflowed the stack when they were passed as arguments.
    const many = Array.from({ length: 70_000 }, (_, index) => String(index));
    const sealed = sealer.seal(new Uint8Array([4]), many);
    expect(opener.open(sealed, many)).toStrictEqual(new Uint8Array([4]));
    expect(refusal(() => opener.open(sealed, many.slice(1)))).toBe(
      "wrong_context"
    );
  });

  const named = {
    length: 3,
    subarray: () => [1, 2, 3],
    [Symbol.toStringTag]: "Uint8Array",
  };

  it.each([
    ["an object that names itself a Uint8Array", named],
    ["bytes of another width", new Uint16Array([1, 2, 3])],
  ])("%s is no value to seal", (_, fake) => {
    expect(
      refusal(() => (asBytes(fake) ? sealer.seal(fake, CONTEXT) : {}))
    ).toBe("invalid_value");
  });

  it.each([
    [
      "an object that names itself a Uint8Array",
      { ciphertext: named, keyId: sealer.keyId },
    ],
    [
      "bytes of another width",
      { ciphertext: new Uint16Array([1, 2, 3]), keyId: sealer.keyId },
    ],
  ])("%s is no ciphertext", (_, sealed) => {
    expect(refusal(() => (asSealed(sealed) ? encode(sealed) : {}))).toBe(
      "malformed"
    );
  });

  it("a key in another base64 spelling of the same bytes is refused", () => {
    // 32 bytes leave the last character before the padding two spare bits
    // (RFC 4648, section 3.5), so three other characters read the same.
    const ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const last = keys.publicKey.at(-2) ?? "";
    const respelled = `${keys.publicKey.slice(0, -2)}${ALPHABET.charAt(ALPHABET.indexOf(last) + 1)}=`;
    expect(Buffer.from(respelled, "base64")).toStrictEqual(
      Buffer.from(keys.publicKey, "base64")
    );
    expect(refusal(() => createSealer(respelled))).toBe("invalid_key");
  });
});
