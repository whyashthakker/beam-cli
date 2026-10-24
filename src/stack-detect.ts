// Works out an app's framework from its files, for `beam monitor --app` without `--stack`.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Stack } from "./monitor-stacks.js";

const read = (dir: string, file: string) => {
  try { return readFileSync(join(dir, file), "utf8"); } catch { return ""; }
};

/** The stack an app directory looks like, or null when nothing says. Cheap: reads a few manifests. */
export function detectStack(dir: string): Stack | null {
  const has = (file: string) => existsSync(join(dir, file));
  if (has("wp-config.php") || has("wp-content")) return "wordpress";
  const pkg = read(dir, "package.json");
  if (pkg) {
    let deps: Record<string, unknown> = {};
    try {
      const json = JSON.parse(pkg) as { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
      deps = { ...json.devDependencies, ...json.dependencies };
    } catch { /* unreadable package.json: fall through to the other manifests */ }
    if ("next" in deps) return "nextjs";
    if ("@nestjs/core" in deps) return "nestjs";
    if ("express" in deps || "fastify" in deps || "koa" in deps || "hono" in deps) return "express";
    if ("vite" in deps) return "vite";
    if (Object.keys(deps).length) return "node";
  }
  const composer = read(dir, "composer.json");
  if (composer) return /"laravel\/framework"/.test(composer) ? "laravel" : "php";
  if (has("manage.py")) return "django";
  const python = read(dir, "requirements.txt") + read(dir, "pyproject.toml") + read(dir, "Pipfile");
  if (/^\s*django\b|["']django/im.test(python)) return "django";
  if (/^\s*fastapi\b|["']fastapi/im.test(python)) return "fastapi";
  if (/^\s*flask\b|["']flask/im.test(python)) return "flask";
  if (/\brails\b/.test(read(dir, "Gemfile"))) return "rails";
  const jvm = read(dir, "pom.xml") + read(dir, "build.gradle") + read(dir, "build.gradle.kts");
  if (jvm) return /spring-boot/.test(jvm) ? "spring" : "java";
  if (has("go.mod")) return "go";
  try {
    if (readdirSync(dir).some(f => /\.(?:csproj|sln|fsproj)$/.test(f))) return "dotnet";
  } catch { /* not a directory we can read */ }
  return null;
}
