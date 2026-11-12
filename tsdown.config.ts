import { defineConfig } from "tsdown";

export default defineConfig({
  dts: true,
  entry: ["src/index.ts"],
  // The package is an ES module, so its files are .js.
  fixedExtension: false,
  format: "esm",
  platform: "neutral",
  sourcemap: true,
});
