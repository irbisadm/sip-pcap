// Check what `npm pack` would publish: only the intended files, and every module
// with its declaration file. Run after `npm run build`.
import { execFileSync } from "node:child_process";

interface PackResult {
  files: { path: string }[];
}

const [{ files }] = JSON.parse(
  execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { encoding: "utf8" }),
) as PackResult[];
const paths = files.map((f) => f.path).sort();

const allowed = [
  /^package\.json$/,
  /^README\.md$/,
  /^LICENSE$/,
  /^CHANGELOG\.md$/,
  /^dist\/(testing\/)?[\w-]+\.(js|d\.ts)$/,
];
const required = [
  "package.json", "README.md", "LICENSE", "CHANGELOG.md",
  "dist/index.js", "dist/index.d.ts", "dist/testing/index.js", "dist/testing/index.d.ts",
];

const problems: string[] = [];
for (const p of paths) if (!allowed.some((re) => re.test(p))) problems.push(`unexpected file: ${p}`);
for (const p of required) if (!paths.includes(p)) problems.push(`missing file: ${p}`);
for (const p of paths.filter((x) => x.endsWith(".js"))) {
  const dts = p.replace(/\.js$/, ".d.ts");
  if (!paths.includes(dts)) problems.push(`no declarations for ${p} (expected ${dts})`);
}

console.log(paths.map((p) => `  ${p}`).join("\n"));
if (problems.length) {
  console.error(`\n${problems.join("\n")}`);
  process.exit(1);
}
console.log(`\n${paths.length} files, as intended`);
