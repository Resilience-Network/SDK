import { rm } from "node:fs/promises";

// Resolve from this file, never from the caller's working directory.
await rm(new URL("../dist/", import.meta.url), { recursive: true, force: true });
