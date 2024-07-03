import typescript from "rollup-plugin-typescript2";
import dts from "rollup-plugin-dts";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import terser from "@rollup/plugin-terser";
import replace from "@rollup/plugin-replace";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default [
  {
    input: "src/index.ts",
    output: [
      {
        file: "dist/index.cjs",
        format: "cjs",
      },
    ],
    plugins: [
      replace({
        preventAssignment: true,
        delimiters: ["", ""],
        "this.getDeviceTokenFromLS()": "this.getDeviceTokenFromEnv()",
      }),
      typescript({
        tsconfig: "./tsconfig.json",
      }),
      terser(),
    ],
  },
  {
    input: "src/index.ts",
    output: [
      {
        file: "dist/index.js",
        format: "es",
      },
      {
        file: "dist/secure-fetch.umd.js",
        name: "YUM",
        extend: true,
        format: "umd",
        globals: {
          "@ugursahinkaya/generic-router": "YUM",
          "@ugursahinkaya/crypto-lib": "YUM",
        },
      },
    ],
    external: ["@ugursahinkaya/generic-router", "@ugursahinkaya/crypto-lib"],
    plugins: [
      typescript({
        tsconfig: "./tsconfig.json",
      }),
      terser(),
    ],
  },
  {
    input: resolve(__dirname, "dist/index.d.ts"),
    output: {
      file: "dist/index.d.ts",
      format: "es",
    },
    plugins: [dts()],
  },
];
