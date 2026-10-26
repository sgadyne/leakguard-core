import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({ plugins: [react()], root: ".", base: "/", build: { outDir: "dist", emptyOutDir: true, sourcemap: false, cssCodeSplit: false, assetsDir: ".", rollupOptions: { input: "index.html", output: { inlineDynamicImports: true, entryFileNames: "app.js", assetFileNames: "app.[ext]" } } } });
