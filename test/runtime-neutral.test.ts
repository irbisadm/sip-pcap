// src/ runs in browsers and Web Workers: no Node APIs, no imports outside the
// declared runtime dependencies, and the main entry does not pull in ./testing.
// (The library tsconfig has no Node types, so tsc catches Node globals as well.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const srcDir = join(root, "src");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
const runtimeDeps = new Set(Object.keys(pkg.dependencies ?? {}));

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name): string[] => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? sourceFiles(p) : p.endsWith(".ts") ? [p] : [];
  });
}

// Drop comments so that prose like "works with Node's Buffer" does not count.
// Good enough for this code base: no string literal in src/ contains "//" or "/*".
const stripComments = (code: string): string =>
  code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

// import/export ... from "x", import "x", import("x"). Between the keyword and `from`
// only an import/export clause (names, `type`, `* as`, braces, commas) is allowed, so
// that `export interface X extends Pick<Y, "from" | "to">` is not taken for an import.
const specifiers = (code: string): string[] => [
  ...[...code.matchAll(/^\s*(?:import|export)\s+[\w$*\s{},]+?\bfrom\s*["']([^"']+)["']/gm)].map((m) => m[1]),
  ...[...code.matchAll(/^\s*import\s*["']([^"']+)["']/gm)].map((m) => m[1]),
  ...[...code.matchAll(/\bimport\s*\(\s*["']([^"']+)["']/g)].map((m) => m[1]),
];

const forbidden: [RegExp, string][] = [
  [/\bBuffer\b/, "Buffer"],
  [/\brequire\s*\(/, "require()"],
  [/\bprocess\./, "process"],
  [/\b__dirname\b|\b__filename\b/, "__dirname/__filename"],
  [/\bglobal\./, "global"],
];

const files = sourceFiles(srcDir);

test("src/ has TypeScript files to check", () => {
  assert.ok(files.length >= 6, `found ${files.length}`);
});

for (const file of files) {
  const name = relative(root, file);
  test(`${name}: no Node APIs`, () => {
    const code = stripComments(readFileSync(file, "utf8"));
    for (const [re, what] of forbidden) assert.doesNotMatch(code, re, `${name} uses ${what}`);
  });

  test(`${name}: imports only relative modules and runtime dependencies`, () => {
    for (const spec of specifiers(stripComments(readFileSync(file, "utf8")))) {
      assert.ok(!spec.startsWith("node:"), `${name} imports ${spec}`);
      if (spec.startsWith("./") || spec.startsWith("../")) continue;
      const pkgName = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      assert.ok(runtimeDeps.has(pkgName), `${name} imports ${spec}, which is not a runtime dependency`);
    }
  });
}

test("the main entry does not import ./testing", () => {
  const seen = new Set<string>();
  const walk = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const spec of specifiers(stripComments(readFileSync(file, "utf8")))) {
      if (spec.startsWith(".")) walk(join(file, "..", spec.replace(/\.js$/, ".ts")));
    }
  };
  walk(join(srcDir, "index.ts"));
  assert.ok(seen.size > 1, "the walk followed the imports");
  const testing = [...seen].filter((f) => relative(srcDir, f).startsWith("testing"));
  assert.deepEqual(testing, []);
});

test("the checker catches what it should", () => {
  assert.match(stripComments('const b = Buffer.from("x");'), /\bBuffer\b/);
  assert.doesNotMatch(stripComments("// Node's Buffer is a Uint8Array"), /\bBuffer\b/);
  assert.deepEqual(
    specifiers('import fs from "node:fs";\nexport {\n  a,\n} from "./a.js";\nimport "x";\nconst m = { f: "from", s: "y" };\nawait import("z");'),
    ["node:fs", "./a.js", "x", "z"],
  );
  assert.deepEqual(
    specifiers('import type { A, type B } from "@s/p";\nexport * from "./b.js";\nexport * as c from "./c.js";\n' +
      'export interface X extends Pick<Y, "from" | "to"> {}\nexport type Z = Pick<Y,\n  "from" | "to">;'),
    ["@s/p", "./b.js", "./c.js"],
  );
});
