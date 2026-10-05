/* Opaque -- sandboxed extraction worker.
 *
 * Runs in a sandboxed page with an opaque origin, embedded by the side panel.
 * It turns things into plain text and locates things in pictures, and that is
 * all: it does not decide what is sensitive and never sees the rules. Deciding
 * happens in the side panel, afterwards, so library code never sits between a
 * value and the decision to redact it.
 *
 * Two models run here:
 *   Florence-2        reads text out of pictures, finds photos and QR codes
 *   bert-small-pii    marks names, places, organisations and other personal
 *                     data in text
 *
 * No code is fetched from the network. The side panel reads the vendored
 * libraries out of the extension package and hands them over; they are loaded
 * from blob: URLs. Model weights come from Hugging Face -- the only host the
 * sandbox may contact -- and are cached by the side panel, because a sandboxed
 * page has no storage of its own that survives a restart.
 */
(function () {
  "use strict";

  /* The parent is the side panel, an extension page. Only it may talk to us. */
  var parentOrigin = (location.ancestorOrigins && location.ancestorOrigins[0]) || "*";
  if (parentOrigin === "null") parentOrigin = "*";

  function post(m, transfer) { parent.postMessage(m, parentOrigin, transfer || []); }
  function log(msg) { post({ type: "LOG", msg: msg }); }

  /* ------------------------------------------------------------ host calls
   * Requests the other way: the worker asks the panel for a library file or a
   * cached model file, and waits for the answer. */
  var hostSeq = 0;
  var hostPending = new Map();

  function host(op, payload, transfer) {
    return new Promise(function (resolve, reject) {
      var rid = "h" + (++hostSeq);
      hostPending.set(rid, { resolve: resolve, reject: reject });
      post(Object.assign({ type: "HOST", rid: rid, op: op }, payload), transfer);
    });
  }

  var blobUrls = {};
  async function libUrl(name) {
    if (!blobUrls[name]) {
      blobUrls[name] = host("lib", { name: name }).then(function (r) {
        return URL.createObjectURL(new Blob([r.buffer], { type: r.type }));
      });
    }
    return blobUrls[name];
  }
  async function importLib(name) { return import(await libUrl(name)); }

  /* Transformers.js hands every downloaded file to this cache. It lives in the
     side panel's origin, which keeps it across browser restarts. */
  var panelCache = {
    match: async function (key) {
      var url = typeof key === "string" ? key : key && key.url;
      if (!/^https:\/\//.test(url || "")) return undefined;
      var r = await host("cache_get", { url: url });
      if (!r || !r.buffer) return undefined;
      return new Response(r.buffer, { status: 200, headers: r.headers || {} });
    },
    put: async function (key, response) {
      var url = typeof key === "string" ? key : key && key.url;
      if (!/^https:\/\//.test(url || "")) return;
      var buffer = await response.arrayBuffer();
      var headers = {};
      response.headers.forEach(function (v, k) {
        if (/^(content-type|etag)$/i.test(k)) headers[k] = v;
      });
      headers["content-length"] = String(buffer.byteLength);
      await host("cache_put", { url: url, buffer: buffer, headers: headers }, [buffer]);
    }
  };

  var TJS = null, tjsLoading = null;
  async function getTransformers() {
    if (TJS) return TJS;
    if (!tjsLoading) {
      tjsLoading = (async function () {
        var mod = await importLib("transformers.min.js");
        var paths = await Promise.all([libUrl("ort-wasm-simd-threaded.jsep.mjs"),
                                       libUrl("ort-wasm-simd-threaded.jsep.wasm")]);
        mod.env.backends.onnx.wasm.wasmPaths = { mjs: paths[0], wasm: paths[1] };
        mod.env.allowLocalModels = false;
        mod.env.useBrowserCache = false;
        mod.env.useCustomCache = true;
        mod.env.customCache = panelCache;
        TJS = mod;
        return mod;
      })().finally(function () { tjsLoading = null; });
    }
    return tjsLoading;
  }

  function progressReporter(onProgress, what) {
    var files = {};
    return function (p) {
      if (!onProgress || !p) return;
      if (p.status === "progress" && p.file && p.total) {
        files[p.file] = [p.loaded || 0, p.total];
        var got = 0, all = 0;
        Object.keys(files).forEach(function (k) { got += files[k][0]; all += files[k][1]; });
        onProgress("downloading " + what + " " + Math.round(got / 1048576) + " of " +
                   Math.round(all / 1048576) + " MB");
      } else if (p.status === "ready") {
        onProgress("starting " + what);
      }
    };
  }

  /* -------------------------------------------------------------- Florence-2
   * The base checkpoint (0.23B), 4-bit wherever that reads correctly. Measured,
   * not guessed: 8-bit embeddings produce empty output on WebGPU, and the q4f16
   * vision encoder misreads IDs (ABCDE1234F became ABCDE12345F). A WebGPU
   * failure falls back to WebAssembly, which reuses every file but the 40 MB
   * embeddings.
   */
  var FLORENCE_ID = "onnx-community/Florence-2-base-ft";
  var florence = null, florenceLoading = null;

  async function hasWebGPU() {
    try { return !!(navigator.gpu && await navigator.gpu.requestAdapter()); }
    catch (_) { return false; }
  }

  async function getFlorence(onProgress) {
    if (florence) return florence;
    if (!florenceLoading) {
      florenceLoading = loadFlorence(onProgress)
        .finally(function () { florenceLoading = null; });
    }
    return florenceLoading;
  }

  async function loadFlorence(onProgress) {
    onProgress && onProgress("starting the model runtime");
    var T = await getTransformers();
    var progress_callback = progressReporter(onProgress, "Florence-2");

    var Q4 = { vision_encoder: "q4", encoder_model: "q4", decoder_model_merged: "q4" };
    var attempts = [];
    if (await hasWebGPU()) {
      attempts.push({ device: "webgpu", dtype: Object.assign({ embed_tokens: "fp16" }, Q4) });
    }
    attempts.push({ device: "wasm", dtype: Object.assign({ embed_tokens: "q8" }, Q4) });
    attempts.push({ device: "wasm", dtype: "q8" });

    var both = await Promise.all([
      T.AutoProcessor.from_pretrained(FLORENCE_ID),
      T.AutoTokenizer.from_pretrained(FLORENCE_ID)
    ]);

    var errors = [];
    for (var i = 0; i < attempts.length; i++) {
      var a = attempts[i];
      try {
        onProgress && onProgress("loading Florence-2 (" + a.device + ")");
        var model = await T.Florence2ForConditionalGeneration.from_pretrained(
          FLORENCE_ID, { device: a.device, dtype: a.dtype, progress_callback: progress_callback });
        florence = { lib: T, model: model, processor: both[0], tokenizer: both[1], device: a.device };
        log("Florence-2 ready on " + a.device);
        return florence;
      } catch (e) {
        /* onnxruntime throws bare numbers, not Errors, when a session fails */
        var why = String((e && e.message) || e);
        errors.push(a.device + ": " + why);
        log("Florence-2 on " + a.device + " failed: " + why);
      }
    }
    throw new Error("Florence-2 could not load\n" + errors.join("\n"));
  }

  /* One model, one session: onnxruntime rejects overlapping runs ("Session
     mismatch" on WebGPU), and attaching two images at once would do exactly
     that. Every generate call therefore waits its turn. */
  var florenceQueue = Promise.resolve();

  async function runTask(f, image, task, phrase, maxTokens) {
    var ti = f.tokenizer(f.processor.construct_prompts(task + (phrase || "")));
    var vi = await f.processor(image);
    var turn = florenceQueue.then(function () {
      return f.model.generate(Object.assign({}, ti, vi, { max_new_tokens: maxTokens }));
    });
    florenceQueue = turn.catch(function () {});
    var ids = await turn;
    var dec = f.tokenizer.batch_decode(ids, { skip_special_tokens: false })[0];
    try {
      return f.processor.post_process_generation(dec, task, image.size)[task] || {};
    } catch (e) {
      /* Transformers.js does not post-process every task (open-vocabulary
         detection among them), but the output is the same label-then-<loc_N>
         form, so read the boxes out directly. */
      var text = dec.replace(/<\/?s>|<pad>/g, "");
      var re = /([^<]*)((?:<loc_\d+>){4})/g;
      var bboxes = [], labels = [], m;
      while ((m = re.exec(text)) !== null) {
        var locs = (m[2].match(/<loc_(\d+)>/g) || []).map(function (x) { return +x.slice(5, -1); });
        bboxes.push(locs.map(function (v, k) { return (v + 0.5) / 1000 * image.size[k % 2]; }));
        labels.push(m[1].trim() || labels[labels.length - 1] || "");
      }
      return { bboxes: bboxes, labels: labels };
    }
  }

  /* Florence-2 resizes its input to a fixed 768 square, so a full page loses
     all small text. Large images are cut into tiles and each is read on its
     own, then boxes are mapped back to original coordinates. Tiles are not
     enlarged first: the model resizes them anyway, and the extra resampling
     measurably cost accuracy (a PAN read as ABCDE123AF instead of ABCDE1234F). */
  async function ocrImage(dataUrl, onProgress) {
    var f = await getFlorence(onProgress);
    var img = await f.lib.RawImage.fromURL(dataUrl);
    var src = img.toCanvas();

    var cols = Math.min(3, Math.max(1, Math.ceil(img.width / 820)));
    var rows = Math.min(3, Math.max(1, Math.ceil(img.height / 820)));
    var total = cols * rows;
    var out = [];
    var done = 0;

    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        done++;
        onProgress && onProgress("reading region " + done + " of " + total);
        var w = img.width / cols, h = img.height / rows;
        var cv = document.createElement("canvas");
        cv.width = Math.round(w);
        cv.height = Math.round(h);
        var g = cv.getContext("2d");
        g.imageSmoothingQuality = "high";
        g.drawImage(src, c * w, r * h, w, h, 0, 0, cv.width, cv.height);
        var tile = await f.lib.RawImage.fromURL(cv.toDataURL("image/png"));

        var res = await runTask(f, tile, "<OCR_WITH_REGION>", "", 768);
        var labels = res.labels || [];
        var quads = res.quad_boxes || [];

        labels.forEach(function (lab, n) {
          var t = String(lab).replace(/<\/?s>/g, "").trim();
          if (!t) return;
          var q = quads[n] || [];
          var xs = q.filter(function (_, k) { return k % 2 === 0; });
          var ys = q.filter(function (_, k) { return k % 2 === 1; });
          var box = null;
          if (xs.length) {
            box = [c * w + Math.min.apply(null, xs), r * h + Math.min.apply(null, ys),
                   c * w + Math.max.apply(null, xs), r * h + Math.max.apply(null, ys)];
          }
          var dup = out.some(function (o) {
            return o.text === t && o.box && box &&
              Math.abs(o.box[0] - box[0]) < 12 && Math.abs(o.box[1] - box[1]) < 12;
          });
          if (!dup) out.push({ text: t, box: box });
        });
      }
    }
    return { regions: out, words: out, text: out.map(function (o) { return o.text; }).join("\n"),
             device: f.device, engine: "florence" };
  }

  /* ---------------------------------------------------------------- grounding
   * Florence-2 does take free text, for a specific job: given a phrase, point
   * at the thing. It is not instruction following; the model is being asked
   * where something is, not what to do about it.
   *
   * Measured on an Aadhaar card: asked for "QR code" or "photograph", it
   * answers with a box around the whole image, while "barcode" and "photo of a
   * person" find exactly the right region. So each thing is asked for by the
   * wording that works first, with the plain phrase kept as a fallback. */
  var PHRASINGS = {
    "photograph": ["photo of a person", "human face", "photograph"],
    "human face": ["human face", "photo of a person"],
    "QR code":    ["barcode", "QR code"],
    "barcode":    ["barcode", "QR code"]
  };

  /* "the aadhaar logo" is asked for as said; the plain thing is the fallback. */
  function phrasingsFor(phrase, qualifier) {
    var base = PHRASINGS[phrase] || [phrase];
    return qualifier ? [qualifier + " " + phrase].concat(base) : base;
  }

  async function groundPhrase(dataUrl, phrase, qualifier, onProgress) {
    var f = await getFlorence(onProgress);
    onProgress && onProgress('looking for "' + phrase + '"');
    var img = await f.lib.RawImage.fromURL(dataUrl);
    var area = img.width * img.height;

    /* A box covering nearly the whole picture is the model's way of not
       knowing, not an answer, so it is discarded and the next wording tried. */
    function usable(b) {
      return b[2] > b[0] && b[3] > b[1] && (b[2] - b[0]) * (b[3] - b[1]) < 0.85 * area;
    }

    var tries = phrasingsFor(phrase, qualifier)
      .map(function (p) { return ["<CAPTION_TO_PHRASE_GROUNDING>", p]; })
      .concat([["<OPEN_VOCABULARY_DETECTION>", phrase]]);

    var out = [];
    for (var i = 0; i < tries.length; i++) {
      var task = tries[i][0], wording = tries[i][1];
      try {
        var res = await runTask(f, img, task, wording, 256);
        (res.bboxes || res.quad_boxes || []).forEach(function (b) {
          var box = b.length === 8
            ? [Math.min(b[0], b[6]), Math.min(b[1], b[3]), Math.max(b[2], b[4]), Math.max(b[5], b[7])]
            : b;
          if (!usable(box)) return;
          var dup = out.some(function (o) {
            return o.box.every(function (v, k) { return Math.abs(v - box[k]) < 12; });
          });
          if (!dup) out.push({ box: box, label: phrase });
        });
        if (out.length) break;          // first wording that finds anything wins
      } catch (e) {
        log("grounding via " + task + " failed: " + e.message);
      }
    }
    return { boxes: out, device: f.device };
  }

  /* ------------------------------------------------------- personal-data model
   * A 4-layer BERT fine-tuned to mark 24 kinds of personal data (person,
   * location, organisation, password, date, age and more). 29 MB at 8 bits and
   * about 25 ms a sentence on the CPU, so it can read every message before it
   * is sent. It runs on WebAssembly deliberately: it is fast enough there, and
   * it keeps the GPU free for Florence-2.
   */
  var NER_ID = "onnx-community/bert-small-pii-detection-ONNX";
  var nerModel = null, nerLoading = null;

  async function getNer(onProgress) {
    if (nerModel) return nerModel;
    if (!nerLoading) {
      nerLoading = (async function () {
        onProgress && onProgress("starting the model runtime");
        var T = await getTransformers();
        var progress_callback = progressReporter(onProgress, "the text model");
        var tokenizer = await T.AutoTokenizer.from_pretrained(NER_ID);
        var model = await T.AutoModelForTokenClassification.from_pretrained(NER_ID,
          { device: "wasm", dtype: "q8", progress_callback: progress_callback });
        var labels = model.config.id2label;
        var oIndex = Object.keys(labels).find(function (k) { return labels[k] === "O"; });
        nerModel = { tokenizer: tokenizer, model: model, labels: labels, oIndex: +oIndex };
        log("text model ready");
        return nerModel;
      })().finally(function () { nerLoading = null; });
    }
    return nerLoading;
  }

  var nerQueue = Promise.resolve();

  async function nerPiece(n, text) {
    var enc = n.tokenizer(text);
    var len = enc.input_ids.dims[1];
    if (len > 510) {
      /* Too many word pieces for one pass (long digit runs, unusual scripts):
         split at the whitespace nearest the middle and read both halves. */
      var mid = text.lastIndexOf(" ", Math.floor(text.length / 2));
      if (mid <= 0) mid = Math.floor(text.length / 2);
      var a = await nerPiece(n, text.slice(0, mid));
      var b = await nerPiece(n, text.slice(mid));
      return a.concat(b.map(function (s) {
        return Object.assign({}, s, { start: s.start + mid, end: s.end + mid });
      }));
    }

    var turn = nerQueue.then(function () { return n.model(enc); });
    nerQueue = turn.catch(function () {});
    var logits = (await turn).logits;
    var T = logits.dims[1], L = logits.dims[2], data = logits.data;
    var ids = Array.from(enc.input_ids.data, Number);
    var toks = n.tokenizer.model.convert_ids_to_tokens(ids);

    var rows = [];
    for (var t = 0; t < T; t++) {
      var max = -Infinity, arg = 0, l;
      for (l = 0; l < L; l++) {
        var v = data[t * L + l];
        if (v > max) { max = v; arg = l; }
      }
      var sum = 0;
      for (l = 0; l < L; l++) sum += Math.exp(data[t * L + l] - max);
      rows.push({ tok: toks[t], label: n.labels[arg], score: 1 / sum });
    }
    return OpaqueNer.spans(text, rows);
  }

  async function ner(text, onProgress) {
    var n = await getNer(onProgress);
    var out = [];
    var parts = OpaqueNer.chunks(text, 900);
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (!p.text.trim()) continue;
      var found = await nerPiece(n, p.text);
      found.forEach(function (s) {
        out.push(Object.assign({}, s, { start: s.start + p.start, end: s.end + p.start }));
      });
    }
    return out;
  }

  /* ---------------------------------------------------------------- documents */

  var pdfjs = null, xlsx = null;

  async function getPdfjs() {
    if (pdfjs) return pdfjs;
    var mod = await importLib("pdf.min.mjs");
    mod.GlobalWorkerOptions.workerSrc = await libUrl("pdf.worker.min.mjs");
    pdfjs = mod;
    return mod;
  }

  function bytesOf(dataUrl) {
    var bin = atob(dataUrl.split(",")[1]);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function extractPdf(dataUrl, onProgress) {
    var lib = await getPdfjs();
    /* No font programs are evaluated as code, whatever the file contains. */
    var doc = await lib.getDocument({ data: bytesOf(dataUrl), isEvalSupported: false,
                                      enableXfa: false }).promise;
    var pages = [];
    var chars = 0;

    for (var i = 1; i <= doc.numPages; i++) {
      onProgress && onProgress("page " + i + " of " + doc.numPages);
      var page = await doc.getPage(i);
      var tc = await page.getTextContent();
      var txt = tc.items.map(function (it) { return it.str; }).join(" ").replace(/\s+/g, " ").trim();
      pages.push("--- page " + i + " ---\n" + txt);
      chars += txt.length;
    }

    /* A PDF of scans has almost no embedded text. Fall back to reading the
       pages as pictures with Florence-2. */
    if (chars < doc.numPages * 24) {
      onProgress && onProgress("no embedded text, reading pages as images");
      var shots = [];
      var limit = Math.min(doc.numPages, 6);
      for (var p = 1; p <= limit; p++) {
        var pg = await doc.getPage(p);
        var vp = pg.getViewport({ scale: 1.8 });
        var cv = document.createElement("canvas");
        cv.width = vp.width; cv.height = vp.height;
        await pg.render({ canvasContext: cv.getContext("2d"), viewport: vp }).promise;
        var r = await ocrImage(cv.toDataURL("image/png"), onProgress);
        shots.push("--- page " + p + " (read as image) ---\n" + r.text);
      }
      return { text: shots.join("\n\n"), scanned: true, pages: doc.numPages };
    }

    return { text: pages.join("\n\n"), scanned: false, pages: doc.numPages };
  }

  /* Returns the grid rather than a flattened string, because column and row
     rules need structure. Flattening happens later, after those rules run. */
  async function extractSheet(dataUrl, onProgress) {
    if (!xlsx) {
      var mod = await importLib("xlsx.mjs");
      xlsx = mod.read ? mod : (mod.default || mod);
    }
    onProgress && onProgress("reading workbook");
    var wb = xlsx.read(bytesOf(dataUrl), { type: "array" });
    var sheets = wb.SheetNames.map(function (sn) {
      var rows = xlsx.utils.sheet_to_json(wb.Sheets[sn], { header: 1, blankrows: false });
      var capped = rows.slice(0, 500).map(function (r) {
        return (r || []).map(function (c) { return c == null ? "" : String(c); });
      });
      return { name: sn, rows: capped, total: rows.length };
    });
    return { sheets: sheets, count: sheets.length };
  }

  /* ---------------------------------------------------------------- messaging */

  window.addEventListener("message", async function (ev) {
    if (ev.source !== parent) return;
    var m = ev.data || {};

    if (m.type === "HOST_RES") {
      var h = hostPending.get(m.rid);
      if (!h) return;
      hostPending.delete(m.rid);
      if (m.ok) h.resolve(m.data); else h.reject(new Error(m.error || "host request failed"));
      return;
    }

    var id = m.id;
    var onProgress = function (msg) { post({ type: "PROGRESS", id: id, msg: msg }); };

    try {
      if (m.type === "WARM") {
        var f = await getFlorence(onProgress);
        post({ type: "WARM_OK", id: id, device: f.device });

      } else if (m.type === "WARM_NER") {
        await getNer(onProgress);
        post({ type: "WARM_OK", id: id, device: "wasm" });

      } else if (m.type === "NER") {
        var spans = await ner(String(m.text || ""), onProgress);
        post({ type: "RESULT", id: id, kind: "ner", spans: spans });

      } else if (m.type === "IMAGE") {
        post(Object.assign({ type: "RESULT", id: id, kind: "image" },
                           await ocrImage(m.dataUrl, onProgress)));

      } else if (m.type === "PDF") {
        post(Object.assign({ type: "RESULT", id: id, kind: "pdf" },
                           await extractPdf(m.dataUrl, onProgress)));

      } else if (m.type === "SHEET") {
        post(Object.assign({ type: "RESULT", id: id, kind: "sheet" },
                           await extractSheet(m.dataUrl, onProgress)));

      } else if (m.type === "GROUND") {
        post(Object.assign({ type: "RESULT", id: id, kind: "ground" },
                           await groundPhrase(m.dataUrl, m.phrase, m.qualifier, onProgress)));

      } else if (m.type === "SCREEN_OCR") {
        post(Object.assign({ type: "RESULT", id: id, kind: "screen" },
                           await ocrImage(m.dataUrl, onProgress)));

      } else if (m.type === "PING") {
        post({ type: "PONG", id: id });
      }
    } catch (err) {
      post({ type: "ERROR", id: id, message: String((err && err.message) || err) });
    }
  });

  post({ type: "READY" });
})();
