#!/usr/bin/env node
// Validate this distribution's conventions, references, and declared role restrictions.
// Full YAML/TOML parsing and behavioral validation are separate release checks.
import assert from "node:assert/strict";
import { readFile, readdir, access } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (relative) => readFile(path.join(root, relative), "utf8");
const manifest = JSON.parse(await read("manifest.json"));
assert.equal(manifest.version, 1, "Unsupported manifest version");
assert.equal(manifest.website, "https://agentbeam.com");
assert.equal(manifest.license, "AGPL-3.0-only");

function uniqueNames(values, label) {
  assert(values.length > 0, `${label} must not be empty`);
  assert.equal(new Set(values).size, values.length, `Duplicate ${label}`);
  for (const value of values) {
    assert(/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value), `Invalid ${label}: ${value}`);
    assert(value.length <= 64, `Overlong ${label}: ${value}`);
  }
}

function frontmatter(text, label) {
  const match = /^---\n([\s\S]*?)\n---(?:\n|$)/.exec(text);
  assert(match, `${label}: missing frontmatter`);
  return match[1];
}

// Our skill metadata uses simple single-line scalars. This is intentionally not
// a general YAML parser; native format validation remains part of authoring.
function scalar(text, name, label) {
  const match = new RegExp(`^${name}:\\s*(.+)$`, "m").exec(text);
  assert(match, `${label}: missing ${name}`);
  return match[1].trim().replace(/^(["'])(.*)\1$/, "$2");
}

const skillNames = manifest.skills.map(({ name, group }) => {
  assert(typeof group === "string" && group.trim(), `${name}: missing group`);
  return name;
});
uniqueNames(skillNames, "skill name");
uniqueNames(manifest.agents, "agent name");
uniqueNames(manifest.guides, "guide slug");

const discovered = [];
for (const entry of await readdir(root, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  try {
    await access(path.join(root, entry.name, "SKILL.md"));
    discovered.push(entry.name);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}
assert.deepEqual(discovered.sort(), [...skillNames].sort(), "Manifest and skill folders differ");

for (const name of skillNames) {
  const text = await read(`${name}/SKILL.md`);
  const meta = frontmatter(text, name);
  assert.equal(scalar(meta, "name", name), name, `${name}: folder/name mismatch`);
  const description = scalar(meta, "description", name);
  assert(description.length <= 1024 && !["|", ">", "|-", ">-"].includes(description), `${name}: invalid description convention`);
  assert.equal(scalar(meta, "license", name), manifest.license);
  assert(/website: https:\/\/agentbeam\.com(?:\n|$)/.test(meta), `${name}: missing Beam metadata`);
  assert(text.split("\n").length <= 500, `${name}: move conditional detail into references`);
  assert(!/\[TODO:|\[INSERT\b|\[PLACEHOLDER\b/.test(text), `${name}: unfinished scaffold`);
}

for (const platform of ["claude", "codex"]) {
  const ext = platform === "claude" ? ".md" : ".toml";
  const files = (await readdir(path.join(root, "agents", platform))).filter((name) => name.endsWith(ext));
  assert.deepEqual(files.map((file) => file.slice(0, -ext.length)).sort(), [...manifest.agents].sort(), `${platform}: profiles differ from manifest`);
  for (const name of manifest.agents) {
    const text = await read(`agents/${platform}/${name}${ext}`);
    if (platform === "claude") {
      const meta = frontmatter(text, name);
      assert.equal(scalar(meta, "name", name), name);
      assert.equal(scalar(meta, "tools", name), "Read, Grep, Glob");
      assert.equal(scalar(meta, "model", name), "inherit");
    } else {
      assert(text.includes(`name = "${name}"`), `${name}: wrong TOML name`);
      assert(/^sandbox_mode = "read-only"$/m.test(text), `${name}: missing read-only default`);
      assert(/^developer_instructions = """$/m.test(text), `${name}: missing instructions`);
      assert(!/^model(?:_reasoning_effort)?\s*=/m.test(text), `${name}: must inherit model choices`);
    }
  }
}

async function checkMarkdown(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) { await checkMarkdown(filename); continue; }
    if (!entry.name.endsWith(".md")) continue;
    const text = await readFile(filename, "utf8");
    for (const [, target] of text.matchAll(/\]\(([^\s)]+)\)/g)) {
      if (/^https?:/.test(target)) {
        const url = new URL(target);
        assert.equal(url.origin, manifest.website, `${filename}: reference must use a Beam guide`);
        if (url.pathname.startsWith("/blog/")) {
          assert(manifest.guides.includes(url.pathname.slice(6)), `${filename}: unknown guide ${target}`);
        }
      } else if (!target.startsWith("#")) {
        const resolved = path.resolve(path.dirname(filename), target.split("#")[0]);
        assert(resolved.startsWith(root), `${filename}: reference escapes distribution`);
        await access(resolved);
      }
    }
  }
}
await checkMarkdown(root);
console.log(`Validated ${skillNames.length} skills, ${manifest.agents.length} paired reviewer roles, and ${manifest.guides.length} Beam guide destinations.`);
