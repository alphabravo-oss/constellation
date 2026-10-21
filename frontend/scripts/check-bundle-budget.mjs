import { log } from "node:console";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";

const root = resolve(import.meta.dirname, "../dist");
const manifest = JSON.parse(await readFile(resolve(root, ".vite/manifest.json"), "utf8"));
const visited = new Set();
const files = new Set();
function visit(key) {
  if (visited.has(key)) return;
  visited.add(key);
  const chunk = manifest[key];
  if (chunk.file.endsWith(".js")) files.add(chunk.file);
  for (const dependency of chunk.imports ?? []) visit(dependency);
}
for (const [key, chunk] of Object.entries(manifest)) if (chunk.isEntry) visit(key);
if (files.size === 0) throw new Error("Bundle budget: no entry JavaScript found");
let total = 0;
for (const file of files) total += gzipSync(await readFile(resolve(root, file))).length;
const budget = 250_000;
log(`Initial JavaScript: ${total} bytes gzip / ${budget} bytes (${files.size} static chunks)`);
if (total > budget) throw new Error("Initial JavaScript exceeds the 250 KB gzip budget");

const chunks = await Promise.all(Object.entries(manifest).filter(([, chunk]) => chunk.file.endsWith(".js")).map(async ([source, chunk]) => ({ source, file: chunk.file, initial: files.has(chunk.file), gzip_bytes: gzipSync(await readFile(resolve(root, chunk.file))).length })));
await writeFile(resolve(root, "bundle-report.json"), JSON.stringify({ initial_gzip_bytes: total, budget_bytes: budget, chunks }, null, 2));
