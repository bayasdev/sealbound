import {
  createOpener,
  createSealer,
  decode,
  encode,
  generateKeys,
  reseal,
} from "../dist/index.js";

// Run by CI on Node.js, Bun and Deno against the built package: a value is
// sealed, written as text, moved to a new key and opened, with nothing but
// the runtime's own globals.
const old = generateKeys();
const next = generateKeys();
const context = ["user", "1", "api-token"];

const stored = encode(
  createSealer(old.publicKey).seal(new TextEncoder().encode("secret"), context)
);

const opener = createOpener({
  retiredSecretKeys: [old.secretKey],
  secretKey: next.secretKey,
});

const moved = reseal(
  { opener, sealer: createSealer(opener.publicKey) },
  decode(stored),
  context
);

const opened = new TextDecoder().decode(
  createOpener({ secretKey: next.secretKey }).open(moved, context)
);

if (opened !== "secret") {
  throw new Error("The value didn't come back");
}

console.log("sealed, moved to a new key and opened");
