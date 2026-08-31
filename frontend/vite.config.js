import { defineConfig } from "vite";

export default defineConfig({
    build: {
        target: "esnext",
        outDir: "../interfaces/Glitter/templates/static/bundle",
        emptyOutDir: true,
        manifest: true,
        minify: true,
        sourcemap: false,
        rollupOptions: {
            input: "src/main.js",
            output: {
                format: "iife",
                entryFileNames: "glitter-[hash].js",
                assetFileNames: "[name][extname]",
            },
        },
    },
});
