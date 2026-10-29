import { writeFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const API_TARGET = process.env.VITE_API_URL ?? "http://localhost:14321";
const OUT_DIR = "../internal/server/webdist";

// emptyOutDir also deletes webdist/.gitkeep, the tracked placeholder that lets
// go:embed compile before any build; put it back once the bundle is written,
// so a build leaves the Git tree clean.
function keepGitkeep(): Plugin {
  return {
    name: "keep-gitkeep",
    apply: "build",
    writeBundle() {
      writeFileSync(new URL(`${OUT_DIR}/.gitkeep`, import.meta.url), "");
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    keepGitkeep(),
  ],
  base: "/",
  build: {
    outDir: OUT_DIR,
    emptyOutDir: true,
    rolldownOptions: {
      output: {
        // Split the framework out of the app bundle. Roughly half of the
        // output is React + the router, which only changes when we bump those
        // deps; keeping them in their own chunks means a new agent-vault
        // release only invalidates the app chunk in the browser cache.
        codeSplitting: {
          groups: [
            {
              name: "vendor-react",
              test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/,
            },
            {
              name: "vendor-router",
              test: /node_modules[\\/]@tanstack[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      "/v1": API_TARGET,
      "/discover": API_TARGET,
      "/health": API_TARGET,
      "/invite": API_TARGET,
    },
  },
});
