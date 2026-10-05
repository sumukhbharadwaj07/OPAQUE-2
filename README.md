# Vendored libraries

Everything the sandboxed worker executes ships inside the extension. Nothing is
fetched from a CDN at runtime, so a compromised or changed package on a CDN
cannot reach the raw files and screenshots the worker handles. The only network
access the sandbox has is to Hugging Face, for model weights, which are data.

The side panel reads these files from the extension package and hands them to
the sandbox, which loads them from `blob:` URLs. That avoids making anything web
accessible.

| File | Package | Source | License |
|---|---|---|---|
| `transformers.min.js` | @huggingface/transformers 3.7.1 | cdn.jsdelivr.net/npm/@huggingface/transformers@3.7.1/dist/ | Apache-2.0 |
| `ort-wasm-simd-threaded.jsep.mjs` | onnxruntime-web 1.22.0-dev.20250409-89f8206ba4 (as shipped in transformers 3.7.1 dist) | same | MIT |
| `ort-wasm-simd-threaded.jsep.wasm` | same | same | MIT |
| `pdf.min.mjs` | pdfjs-dist 4.7.76 | cdn.jsdelivr.net/npm/pdfjs-dist@4.7.76/build/ | Apache-2.0 |
| `pdf.worker.min.mjs` | pdfjs-dist 4.7.76 | same | Apache-2.0 |
| `xlsx.mjs` | SheetJS CE 0.20.3 | cdn.sheetjs.com/xlsx-0.20.3/package/ | Apache-2.0 |

SheetJS is 0.20.3 rather than the npm build 0.18.5, which is affected by
CVE-2023-30533 (prototype pollution) and CVE-2024-22363 (ReDoS). pdf.js 4.7.76
is past CVE-2024-4367, and documents are opened with `isEvalSupported: false`
regardless.

## SHA-256

```
4471bfd47260bea37a61733f6ef385b79087e120e6b61d70ffab6b6bb58de067  transformers.min.js
08fb86ec433c78bfb032c5d84a68b8e8e5a8d81268fa39e24314179a5767a5b9  ort-wasm-simd-threaded.jsep.mjs
c46655e8a94afc45338d4cb2b840475f88e5012d524509916e505079c00bfa39  ort-wasm-simd-threaded.jsep.wasm
49e26487d87a86cb96f6a21740cf7e678bd43db0ccf4e82a6877a806c4d7d5e4  pdf.min.mjs
d2e6ef4cbc6f0e2c1ccb8a4a71d92d09f6242a96a0af07991f08f31e62cc7181  pdf.worker.min.mjs
1a0fb062ee9781b13f6687371b202aaefc53b6ce55b530c027e01f9c087b77db  xlsx.mjs
```

Check them with `shasum -a 256 -c` against the block above, or run
`bash test/all.sh`, which does it for you.

## Models (downloaded on first use, cached by the side panel)

| Model | Used for | Files | Size |
|---|---|---|---|
| onnx-community/Florence-2-base-ft | reading text in pictures, finding photos and QR codes | 4-bit weights, fp16 or 8-bit embeddings | ~215 MB (CPU) / ~255 MB (WebGPU) |
| onnx-community/bert-small-pii-detection-ONNX | names, places, organisations and other personal data in text | `model_quantized.onnx` (8-bit) | ~29 MB |

Both are Apache-2.0.
