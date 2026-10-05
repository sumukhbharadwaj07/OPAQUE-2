/* Opaque -- the leak guard.
 *
 * Decides what in a piece of text is private, how sure it is, and what to put
 * in its place. Every input converges here: typed messages, file text, text
 * read out of pictures, and the description of the screen.
 *
 * A single detector cannot cover the ways people leak things, so several
 * independent readings are layered and then reconciled:
 *
 *   1. Normalise   -- zero-width characters, look-alike letters, values spelled
 *                     out with spaces ("a d i 1 2 3") or in words ("nine eight
 *                     seven ..."), and text written backwards.
 *   2. Detectors   -- checksums and strict formats (Aadhaar, cards, PAN ...).
 *   3. Cues        -- a word that announces a value ("password", "account
 *                     number", "door code") and the slot it points to, in
 *                     either direction, including "from X to Y".
 *   4. Structure   -- key: value, KEY=VALUE, JSON, credentials inside URLs.
 *   5. People      -- names, addresses, employers and birthdays found by the
 *                     sentence around them.
 *   6. Model       -- the personal-data model's spans, graded by context.
 *   7. Shape       -- secret-looking tokens, long account numbers, UPI IDs and
 *                     encoded payloads, with no cue at all.
 *   8. Memory      -- anything masked earlier in the conversation is masked
 *                     again wherever it reappears, reversed, spaced or in parts.
 *
 * Each finding carries a level:
 *   high    masked, no question asked
 *   medium  masked, but the user is shown it before sending and may reveal it
 *   low     not masked; recorded so the user can see it was considered
 *
 * Plus warnings for things that cannot be masked without destroying the
 * question -- a health condition, a hint about how a password is built.
 *
 * Pure functions, no DOM, no network. The model's output is passed in.
 */
var OpaqueGuard = (function () {
  "use strict";

  var D = typeof OpaqueDetect !== "undefined" ? OpaqueDetect : require("./detect.js");
  var L = typeof OpaqueLexicon !== "undefined" ? OpaqueLexicon : require("./lexicon.js");

  var LEVELS = { high: 3, medium: 2, low: 1 };

  /* ------------------------------------------------------------ the view
   * Everything is detected on a cleaned copy of the text, and every offset is
   * mapped back to the original so the right characters get replaced. */

  var INVISIBLE = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/;

  function makeView(text) {
    var s = "", from = [], to = [];
    for (var i = 0; i < text.length;) {
      var cp = text.codePointAt(i);
      var len = cp > 0xffff ? 2 : 1;
      var ch = text.substr(i, len);
      if (!INVISIBLE.test(ch)) {
        var n = ch.normalize("NFKC");
        for (var k = 0; k < n.length; k++) { s += n[k]; from.push(i); to.push(i + len); }
      }
      i += len;
    }
    return { s: s, from: from, to: to, text: text };
  }

  function origSpan(v, a, b) {
    if (b <= a) return null;
    return { start: v.from[a], end: v.to[b - 1] };
  }

  /* Folds look-alike letters and leetspeak, for recognising keywords only. */
  function fold(w) {
    var out = "";
    for (var i = 0; i < w.length; i++) {
      var ch = w[i];
      out += L.CONFUSABLES[ch] || ch;
    }
    return out.toLowerCase();
  }

  /* --------------------------------------------------------------- tokens */

  var TOKEN = /[\p{L}\p{N}@#$\u20b9*\[][\p{L}\p{N}\p{M}@._\-'\u2019\/+#$%&*!~^=\u20b9\]]*|->|=>|:=|[:=,;|\u2192]/gu;

  function tokenize(s) {
    var toks = [], m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(s)) !== null) {
      var raw = m[0], a = m.index;
      /* Sentence punctuation is not part of the value. "!" stays, because
         passwords end in it far more often than questions do. */
      var trimmed = /^\[/.test(raw) ? raw.replace(/[.,;:?'\u2019]+$/, "")
                                    : raw.replace(/[.,;:?'\u2019\]]+$/, "");
      if (!trimmed) continue;
      /* "to23456789", "is:Sunny@1" -- a linking word typed without its
         space would hide the value inside an ordinary-looking word. */
      var glued = /^(to|from|into|and|or|is|was|as|then|now|pin|otp|pwd|pw)([:=]?)(?=[\d@#$%&*!]|[A-Z][a-z]*\d)/i.exec(trimmed);
      if (glued && trimmed.length > glued[0].length + 2) {
        var cut = glued[1].length + glued[2].length;
        toks.push({ a: a, b: a + glued[1].length, raw: glued[1] });
        toks.push({ a: a + cut, b: a + trimmed.length, raw: trimmed.slice(cut) });
        continue;
      }
      toks.push({ a: a, b: a + trimmed.length, raw: trimmed });
    }
    toks.forEach(annotate);
    return mergeRuns(s, toks);
  }

  function annotate(t) {
    t.low = t.raw.toLowerCase();
    t.key = fold(t.raw).replace(/[\u2019]/g, "'");
    t.bare = t.key.replace(/[^a-z0-9']/g, "");
    t.sym = /^(->|=>|:=|[:=,;|\u2192])$/.test(t.raw);
    t.cap = /^\p{Lu}/u.test(t.raw);
    return t;
  }

  /* Values written to dodge a pattern: "a d i 1 2 3", "9 8 7 6 5 4 3 2 1 0",
     "nine eight seven six ...". Each run becomes one token holding the value
     it spells, spanning all of it. */
  function mergeRuns(s, toks) {
    var out = [];
    for (var i = 0; i < toks.length;) {
      /* single characters separated by single spaces or dots */
      var j = i;
      while (j < toks.length && /^[\p{L}\p{N}]$/u.test(toks[j].raw) &&
             (j === i || /^[ .\-_]$/.test(s.slice(toks[j - 1].b, toks[j].a)))) j++;
      if (j - i >= 4) {
        out.push(annotate({ a: toks[i].a, b: toks[j - 1].b, spelled: true,
                            raw: toks.slice(i, j).map(function (t) { return t.raw; }).join("") }));
        i = j;
        continue;
      }
      /* digits said as words, with "double" and "triple" */
      var digits = "", k = i, words = 0;
      while (k < toks.length) {
        var w = toks[k].raw.toLowerCase();
        if (L.MULTIPLIERS[w] && k + 1 < toks.length && L.NUMBER_WORDS[toks[k + 1].raw.toLowerCase()]) {
          var d = L.NUMBER_WORDS[toks[k + 1].raw.toLowerCase()];
          for (var r = 0; r < L.MULTIPLIERS[w]; r++) digits += d;
          k += 2; words += 2;
        } else if (L.NUMBER_WORDS[w] !== undefined) {
          digits += L.NUMBER_WORDS[w]; k++; words++;
        } else if (/^[,\-]$/.test(toks[k].raw) && words) {
          k++;
        } else break;
      }
      if (digits.length >= 3 && words >= 3) {
        out.push(annotate({ a: toks[i].a, b: toks[k - 1].b, spelled: true, raw: digits }));
        i = k;
        continue;
      }
      out.push(toks[i]);
      i++;
    }
    return out;
  }

  /* ----------------------------------------------------------- value tests */

  var TECH = /^(v?\d+(\.\d+)+[a-z]?|\d+(st|nd|rd|th)|\d+(k|m|b|x|gb|mb|kb|tb|hz|ghz|mhz|px|pt|em|rem|ms|s|kg|g|mg|km|m|cm|mm|ml|l|fps|p|mp|w|kw|v|mah|kmph|kmh|mph|lpa|cr|yrs?|min|mins|hrs?|am|pm)|[a-z]+\.(js|ts|py|java|c|cpp|h|go|rs|rb|php|html|css|json|xml|yml|yaml|md|txt|pdf|docx?|xlsx?|pptx?|csv|png|jpe?g|gif|svg|zip|exe|apk|mp3|mp4|wav))$/i;

  function isPlaceholder(v) { return /^\[[A-Z_]+/.test(v); }

  function looksTechnical(v) {
    return TECH.test(v) || /^https?:|^www\./i.test(v) || /^#\w+$/.test(v) ||
           /^@\w+$/.test(v) || /^[\u20b9$\u20ac\u00a3]\s?[\d,.]+[kKmMbB]?$/.test(v) || /^\d+(\.\d+)?%$/.test(v) ||
           /^\d{1,2}[:.]\d{2}([:.]\d{2})?(am|pm)?$/i.test(v) ||
           /^\d{1,4}[\/\-.]\d{1,2}[\/\-.]\d{1,4}$/.test(v);
  }

  function isEmail(v) { return /^[\w.%+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}$/i.test(v); }

  /* How much a token looks like a password on its own, 0 to 1. */
  function secretShape(v) {
    if (!v || v.length < 6 || v.length > 128) return 0;
    if (isPlaceholder(v) || isEmail(v) || looksTechnical(v)) return 0;
    if (/^[a-z_]\w*=[\w.\-]*$/i.test(v)) return 0;                // page=2: an assignment
    var hasL = /\p{L}/u.test(v), hasD = /\d/.test(v), hasS = /[@#$%^&*!?~+]/.test(v);
    var hasU = /\p{Lu}/u.test(v), hasLo = /\p{Ll}/u.test(v);
    var s = 0;
    if (hasL && hasD && hasS) s = 0.6;
    /* No symbol: only a truly random-looking string counts. "iPhone15Pro" is
       a product; "aB3dE9fG2hJ7" is not. */
    else if (hasL && hasD && hasU && hasLo && v.length >= 12 &&
             (v.match(/\d+/g) || []).length >= 2 && D.entropyPerChar(v) > 3.3) s = 0.45;
    else return 0;
    if (v.length >= 10) s += 0.15;
    if (D.entropyPerChar(v) > 3.2) s += 0.15;
    return Math.min(1, s);
  }

  function isCommon(low) {
    return !!(L.COMMON[low] || L.DESCRIPTORS[low] || L.COMMON[low.replace(/'s$/, "")]);
  }

  /* Would this token be accepted as the value of a cue of this kind? Returns
     the level it earns, or null. */
  function valueFor(cat, t, strength, direct) {
    if (!t || t.sym || isPlaceholder(t.raw)) return null;
    var v = t.raw, low = t.low;
    var digits = v.replace(/[\s\-]/g, "");

    switch (cat) {
      case "PIN":
        return /^\d{3,8}$/.test(digits) ? "high" : null;
      case "OTP":
        return /^\d{4,8}$/.test(digits) ? "high" : null;
      case "CVV":
        return /^\d{3,4}$/.test(digits) ? "high" : null;
      case "POSTAL":
        return /^[1-9]\d{5}$/.test(digits) ? "medium" : null;
      case "ACCOUNT":
        if (/^\d{6,20}$/.test(digits)) return "high";
        if (/^[a-z0-9._-]{2,}@[a-z]{2,}$/i.test(v)) return "high";           // UPI
        if (/^[A-Z]{2}\d{2}[A-Z0-9]{8,30}$/i.test(v)) return "high";           // IBAN
        if (/^[A-Z]{4}0[A-Z0-9]{6}$/i.test(v)) return "high";                  // IFSC
        return null;
      case "UPI":
        return /^[a-z0-9._-]{2,}@[a-z][a-z0-9.]{1,}$/i.test(v) ? "high" : null;
      case "ID":
        if (/\d/.test(v) && /^[\p{L}\p{N}\-\/]{4,}$/u.test(v) && !looksTechnical(v)) return "high";
        return null;
      case "USERNAME":
        if (isCommon(low) || v.length < 3 || looksTechnical(v)) return null;
        if (!/^[\p{L}\p{N}._@+\-]+$/u.test(v)) return null;
        if (strength >= 0.85) return "high";
        /* "login" and "handle" are ordinary words; after them only something
           that looks like an identifier counts. */
        return /\d|[._@]|\p{Ll}\p{Lu}/u.test(v) ? "medium" : null;
      case "SECRET":
      case "CREDENTIAL":
        if (L.COMMON_PASSWORDS[low]) return "high";
        if (isEmail(v) || /^https?:/i.test(v)) return null;
        if (isCommon(low) || L.HINT_WORDS[low] || L.RELATIONS[low]) return null;
        if (v.length < 3) return null;
        if (secretShape(v) >= 0.35 || /\d/.test(v) && /\p{L}/u.test(v)) {
          return strength >= 0.6 ? "high" : "medium";
        }
        if (/^\d{4,}$/.test(v)) return strength >= 0.85 ? "high" : "medium";
        /* A plain word: "change my password to aditya". Only right after a
           strong cue is that the secret itself. */
        if (direct && strength >= 0.85) return "high";
        return strength >= 0.6 ? "medium" : null;
    }
    return null;
  }

  /* ---------------------------------------------------------------- cues */

  var CUE_LIST = L.CUES.map(function (c) {
    return { words: c[0].split(/\s+/), cat: c[1], weight: c[2] };
  }).sort(function (a, b) { return b.words.length - a.words.length; });

  function wordMatches(tok, want) {
    var got = tok.bare.replace(/'s$/, "");
    var w = want.replace(/'s$/, "").replace(/[^a-z0-9'\/]/g, "");
    if (want.indexOf("/") !== -1) return tok.low === want;
    if (got === w || got === w + "s" || got === w + "es") return true;
    /* Leetspeak and typos on the longer words: p@ssw0rd, passwrd, oassword. */
    if (w.length >= 6) {
      var n = D.normalizeWord(tok.raw);
      if (n === w) return true;
      var cap = w.length >= 8 ? 2 : 1;
      return D.editDistance(n, w, cap) <= cap || D.editDistance(got, w, cap) <= cap;
    }
    return false;
  }

  function cueAt(toks, i) {
    for (var c = 0; c < CUE_LIST.length; c++) {
      var cue = CUE_LIST[c], ok = true;
      for (var k = 0; k < cue.words.length; k++) {
        var t = toks[i + k];
        if (!t || !wordMatches(t, cue.words[k])) { ok = false; break; }
      }
      if (ok) return { cat: cue.cat, weight: cue.weight, len: cue.words.length };
    }
    /* "pass word", "p a s s w o r d", "passw0rd" -- the old trigger reader
       already handles these approximate forms of the secret words. */
    var joined = "";
    for (var n = 0; n < 3 && toks[i + n]; n++) {
      joined += toks[i + n].raw;
      var t2 = D.triggerScore(joined);
      if (t2 && t2.score >= 0.8 && t2.ph === "SECRET") return { cat: "SECRET", weight: t2.score, len: n + 1 };
    }
    return null;
  }

  var PHRASE_VALUES = { "seed phrase": 1, "recovery phrase": 1, "passphrase": 1, "pass phrase": 1,
                        "security answer": 1, "secret answer": 1 };

  function scanCues(v, toks, add, warn) {
    for (var i = 0; i < toks.length; i++) {
      var cue = cueAt(toks, i);
      if (!cue) continue;
      var cueWords = toks.slice(i, i + cue.len).map(function (t) { return t.low; }).join(" ");
      var cat = cue.cat;
      /* "pin code" next to an address is a postal code, not a secret. */
      if (cat === "PIN" && /code$/.test(cueWords) && /pin\s*code/.test(cueWords)) cat = "POSTAL";

      var j = i + cue.len, skipped = 0, sawLinker = false;
      /* "the old one" / "same as my gmail one" -- a description, not a value. */
      while (j < toks.length && skipped < 5 && (toks[j].sym || L.LINKERS[toks[j].low])) {
        sawLinker = true; j++; skipped++;
      }
      var t = toks[j];
      if (!t) continue;

      var hintWord = t.low.replace(/'s$/, "");
      var nextLow = toks[j + 1] ? toks[j + 1].low.replace(/'s$/, "") : "";
      if ((cat === "SECRET" || cat === "PIN" || cat === "CREDENTIAL") &&
          (L.HINT_WORDS[hintWord] || /^(same|similar|based|made|like)$/.test(t.low) ||
           (/^(my|his|her|our|the)$/.test(t.low) && L.HINT_WORDS[nextLow]))) {
        var endHint = Math.min(toks.length, j + 8);
        warn({ type: "hint", start: toks[i].a, end: toks[endHint - 1].b,
               why: "This describes how a " + (cat === "PIN" ? "PIN" : "password") +
                    " is made, which can be enough to guess it." });
        continue;
      }

      if (PHRASE_VALUES[cueWords]) {
        /* A passphrase or answer can be several words: take the clause. */
        var e = j;
        while (e < toks.length && e - j < 24 && !/^[.;?!]$/.test(v.s.charAt(toks[e].a - 1) || "") &&
               !(e > j && /[.?!]\s*$/.test(v.s.slice(toks[e - 1].b, toks[e].a)))) e++;
        if (e > j) add({ a: toks[j].a, b: toks[e - 1].b, cat: cat === "CREDENTIAL" ? "CREDENTIAL" : "SECRET",
                         level: "high", layer: "cue", ev: 'Follows "' + cueWords + '"' });
        continue;
      }

      var direct = sawLinker || j === i + cue.len;
      var level = valueFor(cat, t, cue.weight, direct);

      /* "the wifi password AT HOME is x", "door code FOR MY BUILDING is 7291":
         a short phrase of ordinary words, then the copula, then the value. */
      if (!level) {
        for (var cj = j, hop = 0, prep = -1; cj < toks.length && hop < 6; cj++, hop++) {
          var ct = toks[cj];
          if (/^(for|on|at|in|of|with|to)$/.test(ct.low)) prep = hop;
          if (/^(is|was|are|were|=|:|->|=>|\u2192)$/.test(ct.low)) {
            var vj = cj + 1;
            while (vj < toks.length && (toks[vj].sym || L.LINKERS[toks[vj].low]) && vj - cj < 4) vj++;
            if (toks[vj] && valueFor(cat, toks[vj], cue.weight, true)) {
              j = vj; t = toks[vj];
              level = valueFor(cat, t, cue.weight, true);
            }
            break;
          }
          /* "for gmail", "on my laptop": a qualifier may name anything */
          var qualifier = prep !== -1 && hop - prep <= 3 && !ct.sym;
          if (!(isCommon(ct.low) || L.ADDRESS_WORDS[ct.low] || L.RELATIONS[ct.low] || qualifier)) break;
          if (/[.?!]$/.test(v.s.slice(ct.b, ct.b + 1))) break;
        }
      }
      /* numbers announced a little earlier: "my PIN for the ATM is 4821" */
      if (!level && /^(PIN|OTP|CVV|ACCOUNT|ID|POSTAL|UPI)$/.test(cat)) {
        for (var nj = j; nj < toks.length && nj - j < 6; nj++) {
          if (/[.?!]\s/.test(v.s.slice(toks[Math.max(j, nj - 1)].b, toks[nj].a + 1))) break;
          var nl = valueFor(cat, toks[nj], cue.weight, false);
          if (nl) { j = nj; t = toks[nj]; level = nl; break; }
        }
      }
      if (!level) {
        /* "password: 'correct horse'" -- a quoted value after a cue. */
        var q = /^\s*[:=]?\s*(["'\u201c\u2018])([^"'\u201d\u2019\n]{1,80})(["'\u201d\u2019])/.exec(v.s.slice(toks[i + cue.len - 1].b));
        if (q && (cat === "SECRET" || cat === "CREDENTIAL" || cat === "USERNAME")) {
          var qa = toks[i + cue.len - 1].b + q.index + q[0].indexOf(q[2]);
          add({ a: qa, b: qa + q[2].length, cat: cat, level: "high", layer: "cue",
                ev: 'Quoted after "' + cueWords + '"' });
        }
        continue;
      }
      add({ a: t.a, b: t.b, val: t.raw, cat: cat, level: level, layer: "cue",
            ev: 'Follows "' + cueWords + '"' });

      /* "from adi123 TO aditya", "4821 or 1284" -- more values joined on. */
      var k = j + 1, more = 0;
      while (k + 1 < toks.length && more < 2 && L.JOINERS[toks[k].low]) {
        var nxt = toks[k + 1];
        if (L.LINKERS[nxt.low] && toks[k + 2]) nxt = toks[k + 2];
        var lv = valueFor(cat, nxt, cue.weight, true);
        if (!lv) break;
        add({ a: nxt.a, b: nxt.b, val: nxt.raw, cat: cat, level: lv, layer: "cue",
              ev: 'Given with the ' + cueWords + ' before it' });
        more++;
        k = toks.indexOf(nxt) + 1;
      }
    }

    /* "same as my gmail password" -- says a password is reused. */
    for (var h = 0; h < toks.length; h++) {
      var cueH = cueAt(toks, h);
      if (!cueH || (cueH.cat !== "SECRET" && cueH.cat !== "PIN")) continue;
      var back = toks.slice(Math.max(0, h - 5), h).map(function (t) { return t.low; });
      if (back.indexOf("same") !== -1 || back.indexOf("similar") !== -1 || back.indexOf("reuse") !== -1 ||
          (back.indexOf("like") !== -1 && back.indexOf("as") === -1)) {
        warn({ type: "hint", start: toks[Math.max(0, h - 5)].a, end: toks[h + cueH.len - 1].b,
               why: "This says a password is shared with another account, which tells an attacker where else it works." });
      }
    }

    /* The other direction: "hunter2 is my password", "use x as the pin". */
    for (var b = 0; b < toks.length; b++) {
      var cueB = cueAt(toks, b);
      if (!cueB) continue;
      var p = b - 1, hops = 0, linkers = [];
      while (p >= 0 && hops < 3 && (toks[p].sym || L.LINKERS[toks[p].low] || /^(use|using|used|for)$/.test(toks[p].low))) {
        linkers.push(toks[p].low); p--; hops++;
      }
      if (p < 0 || !hops) continue;
      var tb = toks[p];
      var isShape = /^(is|was|=|:|as|for)$/.test(linkers[linkers.length - 1] || "") || linkers.indexOf("as") !== -1;
      if (!isShape) continue;
      var lvB = valueFor(cueB.cat, tb, cueB.weight, /^(is|was|=|:)$/.test(linkers[linkers.length - 1]));
      if (lvB) add({ a: tb.a, b: tb.b, val: tb.raw, cat: cueB.cat, level: lvB, layer: "cue",
                     ev: 'Named as "' + toks.slice(b, b + cueB.len).map(function (t) { return t.low; }).join(" ") + '"' });
    }
  }

  /* ------------------------------------------------------------- structure */

  function keyCategory(key) {
    var k = key.toLowerCase().replace(/^["'\s]+|["'\s]+$/g, "").replace(/[\s_\-.]+/g, " ").trim();
    var compact = k.replace(/ /g, "");
    for (var i = 0; i < L.SENSITIVE_KEYS.length; i++) {
      if (L.SENSITIVE_KEYS[i][0].test(compact) || L.SENSITIVE_KEYS[i][0].test(k)) return L.SENSITIVE_KEYS[i][1];
    }
    /* KEY_NAMES_LIKE_THIS in an .env file */
    if (/^[A-Z0-9_]{3,}$/.test(key.trim()) && /PASS|PWD|SECRET|TOKEN|KEY|AUTH|CRED|PRIVATE|SESSION|COOKIE|DSN/.test(key)) {
      return "SECRET";
    }
    return null;
  }

  var KV = /(^|[\n\r,;{(\t]|\s{2,}|^\s*)\s*["']?([A-Za-z][A-Za-z0-9 _.\-\/()]{0,32}?)["']?\s*(:|=|->|=>|\s-\s)\s*(["']?)([^\n\r"'{}]*?)\4(?=\s*(?:[\n\r,;}]|$|\s{2,}|\s+["']?[A-Za-z][A-Za-z0-9 _\-]{0,24}["']?\s*[:=]))/g;

  function scanStructure(v, add) {
    var s = v.s, m;
    KV.lastIndex = 0;
    while ((m = KV.exec(s)) !== null) {
      if (m[0].length === 0) { KV.lastIndex++; continue; }
      var key = m[2], value = m[5];
      if (!value || !value.trim()) continue;
      var cat = keyCategory(key);
      if (!cat) continue;
      var lead = value.length - value.replace(/^\s+/, "").length;
      var val = value.trim();
      if (isPlaceholder(val) || val.length < 1) continue;
      if (/^(null|none|n\/a|na|-|true|false|yes|no|\*+)$/i.test(val)) continue;
      var a = m.index + m[0].lastIndexOf(value) + lead;
      var catOut = cat === "SECRET" && /user|login|handle/i.test(key) ? "USERNAME" : cat;
      if (catOut === "HEALTH" || catOut === "NRP") catOut = catOut === "HEALTH" ? "HEALTH" : "NRP";
      add({ a: a, b: a + val.length, cat: catOut, level: "high", layer: "structure",
            ev: 'Value of "' + key.trim() + '"' });
    }

    /* scheme://user:password@host */
    var U = /\b([a-z][a-z0-9+.\-]*:\/\/)([^\s:@\/]+):([^\s@\/]+)@/gi;
    while ((m = U.exec(s)) !== null) {
      var ua = m.index + m[1].length;
      add({ a: ua, b: ua + m[2].length + 1 + m[3].length, cat: "CREDENTIAL", level: "high",
            layer: "structure", ev: "Credentials inside a URL" });
    }
    /* ?token=...&key=... */
    var Q = /[?&](access_token|token|api_key|apikey|key|auth|sig|signature|password|pwd|passwd|secret|session|sid|code|otp)=([^&#\s]{4,})/gi;
    while ((m = Q.exec(s)) !== null) {
      var qa = m.index + m[0].length - m[2].length;
      add({ a: qa, b: qa + m[2].length, cat: "CREDENTIAL", level: "high", layer: "structure",
            ev: 'URL parameter "' + m[1] + '"' });
    }
  }

  /* ---------------------------------------------------------------- people */

  function tailWords(s, a, n) {
    var pre = s.slice(Math.max(0, a - 60), a).toLowerCase().replace(/[\u2019]/g, "'");
    var words = pre.match(/[\p{L}\p{N}'\-\/.]+|[:,]/gu) || [];
    return words.slice(-n);
  }

  function endsWithPhrase(words, phrases) {
    var joined = " " + words.join(" ").replace(/\s+([:,])/g, "$1") + " ";
    return phrases.some(function (p) {
      var pj = " " + p + " ";
      return joined.slice(-pj.length) === pj || joined.slice(-pj.length - 1).replace(/[:,] $/, " ") === pj;
    });
  }

  /* What the words before a span say about it. */
  function contextOf(s, a) {
    var w = tailWords(s, a, 6);
    var last = w[w.length - 1] || "", prev = w[w.length - 2] || "";
    var ctx = { personal: false, isPublic: false, relation: null, work: false, from: false,
                birth: false, address: false, self: false };
    if (endsWithPhrase(w, L.NAME_INTROS)) ctx.personal = true;
    if (L.RELATIONS[last.replace(/'s$/, "")] || (L.RELATIONS[prev.replace(/'s$/, "")] && /^(is|was|named|called|name|:)$/.test(last)) ||
        (/^(name|is)$/.test(last) && w.some(function (x) { return L.RELATIONS[x.replace(/'s$/, "")]; }))) {
      ctx.personal = true;
      ctx.relation = last;
    }
    if (L.HONORIFICS[last.replace(/\.$/, "")]) ctx.personal = true;
    if (w.some(function (x) { return L.PUBLIC_CONTEXT[x]; }) && !/^(my|our)$/.test(prev)) ctx.isPublic = true;
    if (endsWithPhrase(w, L.WORK_CUES)) ctx.work = true;
    if (endsWithPhrase(w, L.FROM_CUES)) ctx.from = true;
    if (w.some(function (x) { return L.BIRTH_CUES.indexOf(x) !== -1; }) ||
        endsWithPhrase(w, L.BIRTH_CUES)) ctx.birth = true;
    /* "I live AT x" introduces an address; "I live IN x" only a place. */
    if (endsWithPhrase(w, L.ADDRESS_CUES.filter(function (c) { return !/ in$/.test(c); }))) ctx.address = true;
    if (/^(i'm|im|aged|turned|turning)$/.test(last) || (last === "am" && prev === "i") ||
        (/^(is|:|=)$/.test(last) && prev === "age") || (last === "age" && /^(my|his|her)$/.test(prev))) {
      ctx.self = true;
    }
    return ctx;
  }

  var NAME_TOKEN = /^(\p{Lu}[\p{L}'\-]*\.?|\p{Lu}\.)$/u;

  function nameRun(toks, i, allowLower) {
    var j = i, words = 0;
    while (j < toks.length && words < 4) {
      var t = toks[j];
      if (t.sym || isPlaceholder(t.raw)) break;
      var capOk = NAME_TOKEN.test(t.raw) && !isCommon(t.low.replace(/\.$/, ""));
      var lowOk = allowLower && /^\p{Ll}[\p{L}'\-]+$/u.test(t.raw) && !isCommon(t.low) &&
                  !/(ing|ed|ly)$/.test(t.low) && t.raw.length >= 3;
      if (!(capOk || lowOk)) break;
      j++; words++;
    }
    return j;
  }

  function scanPeople(v, toks, add) {
    var s = v.s;
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      var ctx = null;

      /* names announced by the sentence */
      if ((NAME_TOKEN.test(t.raw) && !isCommon(t.low)) || true) {
        ctx = contextOf(s, t.a);
        if (ctx.personal && !ctx.isPublic) {
          /* Lowercase names only after an explicit introduction; after "my
             son" a lowercase word is more often a verb ("my son loves ...").
             The model covers lowercase names in that position. */
          var strongIntro = endsWithPhrase(tailWords(s, t.a, 5),
            ["my name is", "my name's", "call me", "my full name is", "my surname is",
             "my last name is", "my first name is", "name is"]);
          var j = nameRun(toks, i, strongIntro);
          if (j > i && !(j === i + 1 && toks[i].raw.length < 2)) {
            add({ a: toks[i].a, b: toks[j - 1].b, cat: "NAME", level: "high", layer: "people",
                  ev: ctx.relation ? 'Named as your ' + ctx.relation : "Introduced as a name" });
            i = j - 1;
            continue;
          }
        }
      }

      /* where they work or study */
      if (ctx && ctx.work && NAME_TOKEN.test(t.raw) && !isCommon(t.low)) {
        var e = i;
        while (e < toks.length && e - i < 5 &&
               (NAME_TOKEN.test(toks[e].raw) || /^(&|and|of|the)$/.test(toks[e].low) && toks[e + 1] && NAME_TOKEN.test(toks[e + 1].raw))) e++;
        add({ a: t.a, b: toks[e - 1].b, cat: "ORG", level: "medium", layer: "people",
              ev: "Where you work or study" });
        i = e - 1;
        continue;
      }

      /* where they are from */
      if (ctx && ctx.from && NAME_TOKEN.test(t.raw) && !isCommon(t.low)) {
        var f = i;
        while (f < toks.length && f - i < 3 && NAME_TOKEN.test(toks[f].raw) && !isCommon(toks[f].low)) f++;
        add({ a: t.a, b: toks[f - 1].b, cat: "PLACE", level: "medium", layer: "people",
              ev: "Where you live or come from" });
        i = f - 1;
        continue;
      }

      /* age about themselves: "I'm 34", "34 years old" */
      if (/^\d{1,3}$/.test(t.raw) && +t.raw > 0 && +t.raw < 120) {
        var after = s.slice(t.b, t.b + 16).toLowerCase();
        if (ctx && ctx.self && !/^\s*(%|am|pm|:|\.\d|kg|km|lpa|lakh|k\b|rs|inr|rupees|crore|cr\b|\$|dollars|hours|hrs|mins|minutes|days|weeks|months)/.test(after) ||
            /^\s*(years?|yrs?)\s*(old|of age)/.test(after) && /\b(i|i'm|im|i am|my|he|she|son|daughter)\b/.test(s.slice(Math.max(0, t.a - 30), t.a).toLowerCase())) {
          var ae = /^\s*(years?|yrs?)\s*(old|of age)/.exec(after);
          add({ a: t.a, b: ae ? t.b + ae[0].length : t.b, cat: "AGE", level: "medium", layer: "people",
                ev: "An age given about a person" });
        }
      }
    }

    /* personal amounts: "my salary is 18 LPA", "I earn Rs50,000 a month" */
    var MONEY_CUE = /\b(my|our|his|her|i|we)\s+(?:(?:current|monthly|annual|yearly|total|net|gross|take[- ]home|new|old|expected)\s+)*(salary|ctc|income|pay|package|stipend|rent|loan|emi|debt|balance|savings|net\s*worth|bonus|earnings?|earn|earns|make|makes|made|get paid|am paid|owe|owes|spent|spend)\b[^.\n]{0,24}?((?:\u20b9|rs\.?|inr|\$|\u20ac|\u00a3)\s?[\d,]+(?:\.\d+)?(?:\s?(?:k|lakhs?|lacs?|crores?|cr|lpa|l|million|m))?|\d[\d,.]*\s?(?:k|lakhs?|lacs?|crores?|cr|lpa|l|thousand|million|rupees|dollars|per month|a month|pm|pa)\b)/gi;
    var mm;
    while ((mm = MONEY_CUE.exec(s)) !== null) {
      var amt = mm[3], ai = mm.index + mm[0].length - amt.length;
      add({ a: ai, b: ai + amt.length, cat: "FINANCIAL", level: "medium", layer: "people",
            ev: "A personal amount (" + mm[2].toLowerCase() + ")" });
    }

    /* dates of birth written in words: "born on 12 March 1998", "dob: March 12, 1998" */
    var MONTH = "(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
    var DATE = new RegExp("\\b(?:\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?" + MONTH + "\\.?,?(?:\\s+\\d{2,4})?|" +
                          MONTH + "\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?(?:,?\\s+\\d{2,4})?|" +
                          "\\d{1,2}[\\/\\-.]\\d{1,2}[\\/\\-.]\\d{2,4}|\\d{4}-\\d{2}-\\d{2})\\b", "gi");
    var m;
    while ((m = DATE.exec(s)) !== null) {
      var c = contextOf(s, m.index);
      if (c.birth) {
        add({ a: m.index, b: m.index + m[0].length, cat: "DOB", level: "high", layer: "people",
              ev: "A date of birth" });
      }
    }
  }

  /* -------------------------------------------------------------- addresses
   * Indian addresses have a grammar of their own -- H.No, Flat, Sector, Nagar,
   * Dist, Tal, a six-digit PIN -- which rules capture better than a model
   * trained mostly on Western addresses. A line counts as an address when it
   * carries enough of that vocabulary, and lines of an address block that
   * follow it are pulled in with it. */

  var PINCODE = /\b[1-9]\d{2}\s?\d{3}\b/;

  function addressScore(line) {
    var proper = (line.match(/\b\p{Lu}\p{Ll}{2,}/gu) || []).filter(function (w) {
      return !isCommon(w.toLowerCase());
    }).length;
    var words = line.toLowerCase().match(/[a-z]\/[a-z]|[a-z]+(?:\.[a-z]+)*\.?|\d+[a-z]?(?:\/\d+)?/g) || [];
    var hits = 0, strong = 0, num = false;
    words.forEach(function (w) {
      var bare = w.replace(/\.$/, ""), flat = bare.replace(/\./g, "");
      var isStrong = L.ADDRESS_STRONG[w] || L.ADDRESS_STRONG[bare] || L.ADDRESS_STRONG[flat];
      if (isStrong) { strong++; hits++; }
      else if (L.ADDRESS_WORDS[w] || L.ADDRESS_WORDS[bare] || L.ADDRESS_WORDS[flat]) hits += 0.5;
      if (/^\d+[a-z]?(\/\d+)?$/.test(w) || /^\d+(st|nd|rd|th)$/.test(w)) num = true;
    });
    if (/#\s?\d+|\bno\.?\s?\d+/i.test(line)) num = true;
    var pin = PINCODE.test(line);
    return { hits: hits, strong: strong, num: num, pin: pin, proper: proper };
  }

  /* Where the address itself starts inside a line: past "I stay at", "our
     office address is", at the first number, address word or proper name. */
  function addressStart(text) {
    var cue = /^(.*?\b(?:address(?:\s+is)?|live[sd]?\s+(?:at|in)|stay(?:ing)?\s+(?:at|in)|resid(?:e|ing)\s+at|located\s+at|deliver\s+to|ship\s+to|bill\s+to|send\s+(?:it\s+)?to)\s*[:\-]?\s*)/i.exec(text);
    if (cue && cue[1].length < text.length) return cue[1].length;
    var m = /\d|\b(?:flat|house|h\.?\s?no|plot|door|shop|room|s\/o|d\/o|w\/o|c\/o|at\s+post|near|opp)\b|\p{Lu}\p{Ll}/iu.exec(text);
    return m ? m.index : 0;
  }

  function scanAddresses(v, add, nerSpans) {
    var s = v.s;
    /* announced: "my address is ...", "I live at ...", "deliver to ..." */
    var lower = s.toLowerCase();
    L.ADDRESS_CUES.forEach(function (cue) {
      var idx = -1;
      while ((idx = lower.indexOf(cue, idx + 1)) !== -1) {
        if (idx > 0 && /[\p{L}\p{N}]/u.test(lower[idx - 1])) continue;
        var a = idx + cue.length;
        while (a < s.length && /[\s:,\-]/.test(s[a])) a++;
        var copula = /^(?:is|was|are|=)\s+/i.exec(s.slice(a));
        if (copula) a += copula[0].length;
        var end = a;
        while (end < s.length && end - a < 180 && s[end] !== "\n" &&
               !(/[.?!]/.test(s[end]) && (end + 1 >= s.length || /\s/.test(s[end + 1])) &&
                 !/\b(no|h|p|o|st|rd|opp|dist|tal|nr|flat|apt|sec)$/i.test(s.slice(a, end)))) end++;
        var chunk = s.slice(a, end);
        if (!chunk.trim()) continue;
        var sc = addressScore(chunk);
        var isLiveIn = /(live|stay) in$/.test(cue);
        if (isLiveIn && sc.strong === 0 && !sc.num && !sc.pin) continue;   // "I live in Pune" is a place, not an address
        add({ a: a, b: a + chunk.replace(/[\s,]+$/, "").length, cat: "ADDRESS", level: "high",
              layer: "address", ev: 'Follows "' + cue + '"' });
      }
    });

    /* unannounced address lines, and the block they belong to */
    var lines = [], pos = 0;
    s.split(/(\n)/).forEach(function (part) {
      if (part === "\n") { pos += 1; return; }
      lines.push({ a: pos, text: part });
      pos += part.length;
    });
    var inBlock = false;
    lines.forEach(function (ln) {
      var text = ln.text;
      if (!text.trim()) { inBlock = false; return; }
      var sc = addressScore(text);
      var hasLoc = (nerSpans || []).some(function (n) {
        return n.label === "LOCATION" && n.a >= ln.a && n.b <= ln.a + text.length;
      });
      var strong = (sc.strong >= 1 && sc.hits >= 2 && (sc.num || sc.pin)) ||
                   (sc.strong >= 2 && sc.hits >= 3 && (sc.proper || sc.num)) ||
                   (sc.pin && (sc.strong >= 1 || hasLoc));
      var cont = inBlock && (sc.hits >= 1 || sc.pin || hasLoc) && text.length < 120;
      var header = /^\s*(address|addr|pata|\u092a\u0924\u093e)\s*[:\-]?\s*$/i.test(text);
      if (header) { inBlock = true; return; }
      if ((strong || cont) && text.length <= 200) {
        var body = text.trim().replace(/^(address|addr)\s*[:\-]\s*/i, "");
        body = body.slice(addressStart(body));
        var a = ln.a + text.indexOf(body);
        /* "Ananya Iyer, 14 MG Road, ..." -- a name heading the line is the
           addressee, kept as its own finding. */
        var who = (nerSpans || []).filter(function (n) {
          return n.label === "PERSON" && n.a === a && n.score >= 0.6;
        })[0];
        if (who) {
          var rest = s.slice(who.b, a + body.length);
          var skip = rest.length - rest.replace(/^[\s,;:\-]+/, "").length;
          if (addressScore(rest).hits >= 1 || PINCODE.test(rest)) {
            add({ a: who.a, b: who.b, cat: "NAME", level: "high", layer: "address",
                  ev: "The name an address is written to" });
            body = rest.slice(skip);
            a = who.b + skip;
          }
        }
        add({ a: a, b: a + body.replace(/[\s,]+$/, "").length, cat: "ADDRESS", level: "high",
              layer: "address", ev: strong ? "Reads as a postal address" : "Continues an address" });
        inBlock = true;
      } else {
        inBlock = false;
      }
    });
  }

  /* ----------------------------------------------------------------- model */

  var NER_MAP = {
    PERSON: "NAME", LOCATION: "PLACE", ORGANIZATION: "ORG", DATE_TIME: "DATE", AGE: "AGE",
    PASSWORD: "SECRET", EMAIL_ADDRESS: "EMAIL", PHONE_NUMBER: "PHONE", CREDIT_CARD: "CARD",
    IBAN_CODE: "ACCOUNT", US_BANK_NUMBER: "ACCOUNT", FINANCIAL: "ACCOUNT", IP_ADDRESS: "IP",
    MAC_ADDRESS: "IP", IMEI: "ID", COORDINATE: "COORD", URL: "URL", US_SSN: "ID", US_ITIN: "ID",
    US_PASSPORT: "ID", US_DRIVER_LICENSE: "ID", US_LICENSE_PLATE: "ID", NRP: "NRP", TITLE: null
  };

  function scanModel(v, spans, add, warn, toks) {
    var s = v.s;
    (spans || []).forEach(function (sp) {
      var cat = NER_MAP[sp.label];
      if (!cat) return;
      var a = sp.a, b = sp.b, score = sp.score;
      var text = s.slice(a, b);
      if (!text.trim() || isPlaceholder(text)) return;
      var ctx = contextOf(s, a);
      var level = null, ev = "Personal-data model: " + sp.label.toLowerCase().replace(/_/g, " ") +
                             " (" + Math.round(score * 100) + "%)";

      switch (cat) {
        case "NAME":
          if (score < 0.3) return;
          var words = text.trim().split(/\s+/).filter(function (w) { return /\p{L}{2,}/u.test(w); });
          if (!words.length || words.every(function (w) { return isCommon(w.toLowerCase()); })) return;
          if (ctx.isPublic) level = "low";
          else if (ctx.personal || ctx.relation) level = "high";
          else if (words.length >= 2 && score >= 0.8) level = "medium";
          else level = "low";
          break;
        case "PLACE":
          if (score < 0.4) return;
          level = ctx.address ? "high" : (ctx.from ? "medium" : "low");
          break;
        case "ORG":
          if (score < 0.5) return;
          level = ctx.work ? "medium" : "low";
          break;
        case "DATE":
          if (score < 0.5) return;
          if (ctx.birth) { cat = "DOB"; level = "high"; } else level = "low";
          break;
        case "AGE":
          level = ctx.self ? "medium" : "low";
          break;
        case "SECRET":
          if (isCommon(text.toLowerCase())) return;
          level = score >= 0.6 ? "high" : score >= 0.35 ? "medium" : null;
          break;
        case "NRP":
          if (score >= 0.6) warn({ type: "topic", topic: "BELIEF", start: a, end: b,
                                   why: "Mentions nationality, religion or politics." });
          return;
        case "URL":
          level = "low";
          break;
        default:
          level = score >= 0.7 ? "high" : score >= 0.45 ? "medium" : null;
      }
      if (level) add({ a: a, b: b, cat: cat, level: level, layer: "model", score: score, ev: ev });
    });
  }

  /* ----------------------------------------------------------------- shape */

  var UPI_HANDLES = /^(ok[a-z]+|ybl|ibl|axl|apl|upi|paytm|pt[a-z]+|icici|hdfcbank|sbi|axisbank|kotak|yesbank|idfcbank|federal|indus|rbl|fam|slice|freecharge|airtel|jio|postbank|barodampay|cnrb|pnb|boi|mahb|kbl|ikwik|wa[a-z]+|naviaxis|superyes|jupiteraxis|abfspay|timecosmos|pingpay|dbs|aubank|equitas|allbank|unionbank|centralbank|indianbank|uco|kvb|tjsb|dlb|citi|hsbc|sc|jkb)$/i;

  function scanShape(v, toks, add, analyzeInner) {
    toks.forEach(function (t) {
      var raw = t.raw;
      /* UPI IDs: name@bank, no dot after the @ */
      var up = /^([a-z0-9][a-z0-9._-]{1,63})@([a-z][a-z0-9]{1,30})$/i.exec(raw);
      if (up) {
        var known = UPI_HANDLES.test(up[2]);
        add({ a: t.a, b: t.b, cat: "UPI", level: known ? "high" : "medium", layer: "shape",
              ev: known ? "UPI ID" : "Looks like a UPI ID or handle" });
        return;
      }
      var decoded = decodeToken(raw);
      if (decoded && analyzeInner) {
        var inner = analyzeInner(decoded);
        if (inner.some(function (x) { return LEVELS[x.level] >= 2; })) {
          add({ a: t.a, b: t.b, cat: "ENCODED", level: "high", layer: "shape",
                ev: "Encoded text that contains a " + inner[0].kind.toLowerCase() });
          return;
        }
      }
      var sh = secretShape(raw);
      if (sh >= 0.55) {
        add({ a: t.a, b: t.b, cat: "SECRET", level: sh >= 0.9 ? "high" : "medium", layer: "shape",
              ev: "Looks like a password (letters, digits and symbols)" });
        return;
      }
      /* long bare numbers: account numbers, customer IDs */
      var dg = raw.replace(/[\s\-]/g, "");
      if (/^\d{11,18}$/.test(dg) && !/^(19|20)\d{2}(0[1-9]|1[0-2])/.test(dg.slice(0, 6))) {
        add({ a: t.a, b: t.b, cat: "ACCOUNT", level: "medium", layer: "shape",
              ev: "A long number, possibly an account or ID number" });
        return;
      }
      /* digits said as words or one at a time: validate what they spell */
      if (t.spelled && /^\d+$/.test(raw)) {
        var sp = numberKind(raw);
        if (sp) {
          add({ a: t.a, b: t.b, cat: sp[0], level: "high", layer: "shape", ev: sp[1] + ", spelled out" });
        } else if (raw.length >= 6) {
          add({ a: t.a, b: t.b, cat: "NUMBER", level: "medium", layer: "shape",
                ev: "A long number, spelled out" });
        }
        return;
      }
      /* a spelled-out value: "a d i 1 2 3" */
      if (t.spelled && /\p{L}/u.test(raw) && /\d/.test(raw)) {
        add({ a: t.a, b: t.b, val: raw, cat: "SECRET", level: "medium", layer: "shape",
              ev: "Spelled out character by character" });
        return;
      }
    });

    var s = v.s, m;
    /* digits in groups a pattern would miss: 98-76-54-32-10, 9 8 7 6 ... */
    var RUN = /\d(?:[ .\-\/]?\d){9,18}/g;
    while ((m = RUN.exec(s)) !== null) {
      var nk = numberKind(m[0].replace(/\D/g, ""));
      if (nk) add({ a: m.index, b: m.index + m[0].length, cat: nk[0], level: "high", layer: "shape",
                    ev: nk[1] + ", spaced out" });
    }
    /* IPv4, MAC, coordinates */
    var IP = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
    while ((m = IP.exec(s)) !== null) {
      if (/\d\.\d+\.\d+\.\d+\.\d/.test(s.slice(Math.max(0, m.index - 2), m.index + m[0].length + 2))) continue;
      add({ a: m.index, b: m.index + m[0].length, cat: "IP", level: "medium", layer: "shape", ev: "IP address" });
    }
    var MAC = /\b[0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}\b/gi;
    while ((m = MAC.exec(s)) !== null) {
      add({ a: m.index, b: m.index + m[0].length, cat: "IP", level: "medium", layer: "shape", ev: "MAC address" });
    }
    var GEO = /-?\b\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b/g;
    while ((m = GEO.exec(s)) !== null) {
      add({ a: m.index, b: m.index + m[0].length, cat: "COORD", level: "medium", layer: "shape", ev: "GPS coordinates" });
    }
  }

  /* What a bare run of digits is, if its length and checksum say so. */
  function numberKind(d) {
    if (d.length === 10 && /^[6-9]/.test(d)) return ["PHONE", "Mobile number"];
    if (d.length === 12 && D.verhoeff(d)) return ["AADHAAR", "Aadhaar number (Verhoeff passes)"];
    if (d.length >= 13 && d.length <= 19 && D.luhn(d)) return ["CARD", "Card number (Luhn passes)"];
    return null;
  }

  function decodeToken(raw) {
    var out = null;
    try {
      if (/^[A-Za-z0-9+\/]{16,}={0,2}$/.test(raw) && raw.length % 4 === 0 && /[A-Z]/.test(raw) && /[a-z0-9]/.test(raw)) {
        out = typeof atob === "function" ? atob(raw) : Buffer.from(raw, "base64").toString("binary");
      } else if (/^(0x)?(?:[0-9a-f]{2}){8,}$/i.test(raw)) {
        var h = raw.replace(/^0x/i, ""), str = "";
        for (var i = 0; i < h.length; i += 2) str += String.fromCharCode(parseInt(h.substr(i, 2), 16));
        out = str;
      } else if (/%[0-9a-f]{2}/i.test(raw)) {
        out = decodeURIComponent(raw);
        if (out === raw) out = null;
      }
    } catch (e) { return null; }
    if (!out) return null;
    var printable = out.replace(/[^\x20-\x7e]/g, "").length;
    return printable / out.length >= 0.9 && /[a-z0-9]/i.test(out) ? out : null;
  }

  /* ---------------------------------------------------------------- topics */

  function scanTopics(v, toks, warn, add, forced) {
    var byTopic = {};
    toks.forEach(function (t) {
      Object.keys(L.TOPICS).forEach(function (topic) {
        if (L.TOPICS[topic][t.low] || L.TOPICS[topic][t.low.replace(/s$/, "")]) {
          (byTopic[topic] = byTopic[topic] || []).push(t);
        }
      });
    });
    Object.keys(byTopic).forEach(function (topic) {
      var ts = byTopic[topic];
      if (topic === "MONEY" && !/\b(my|our|i|i'm|me)\b/i.test(v.s)) return;
      if (topic === "HEALTH" && !/\b(my|i|i'm|me|mine|our|he|she|his|her|son|daughter|wife|husband|mom|dad|mother|father)\b/i.test(v.s)) return;
      if (forced[topic]) {
        ts.forEach(function (t) {
          add({ a: t.a, b: t.b, cat: topic === "HEALTH" ? "HEALTH" : topic, level: "high", layer: "rule",
                ev: "Your rule hides " + L.TOPIC_LABEL[topic] });
        });
        return;
      }
      warn({ type: "topic", topic: topic, start: ts[0].a, end: ts[ts.length - 1].b,
             words: ts.map(function (t) { return t.raw; }),
             why: "Mentions " + L.TOPIC_LABEL[topic] + ": " +
                  ts.slice(0, 4).map(function (t) { return t.raw; }).join(", ") + "." });
    });
  }

  /* ---------------------------------------------------------------- memory
   * What was masked earlier in the conversation, so the same value is caught
   * again however it comes back: whole, reversed, spaced out, or in pieces
   * ("the first part is adi ... the rest is 123"). Held in memory only; the
   * side panel keeps it in session storage, never on disk. */

  var REMEMBER = { SECRET: 1, CREDENTIAL: 1, PIN: 1, OTP: 1, CVV: 1, ACCOUNT: 1, UPI: 1, ID: 1,
                   USERNAME: 1, NAME: 1, ADDRESS: 1, CARD: 1, AADHAAR: 1, PHONE: 1, EMAIL: 1,
                   ENCODED: 1, TERM: 1 };

  function createMemory(data) {
    data = data || {};
    return { entries: (data.entries || []).slice(), counters: Object.assign({}, data.counters || {}),
             numbers: Object.assign({}, data.numbers || {}), allow: (data.allow || []).slice() };
  }

  function compact(v) { return String(v).toLowerCase().replace(/[^\p{L}\p{N}]/gu, ""); }

  function remember(mem, item) {
    if (!mem || !REMEMBER[item.cat]) return;
    var c = compact(item.value);
    if (c.length < 3) return;
    if (mem.entries.some(function (e) { return e.c === c; })) return;
    mem.entries.push({ c: c, cat: item.cat, ph: item.ph });
    /* Remember a full name's parts too: "Vilas Rakhe" then "Vilas". */
    if (item.cat === "NAME") {
      item.value.split(/\s+/).forEach(function (part) {
        var pc = compact(part);
        if (pc.length >= 3 && !isCommon(part.toLowerCase()) && !L.COMMON_NAME_PARTS[pc] &&
            !mem.entries.some(function (e) { return e.c === pc; })) {
          mem.entries.push({ c: pc, cat: "NAME", ph: item.ph, part: true });
        }
      });
    }
    if (mem.entries.length > 400) mem.entries.splice(0, mem.entries.length - 400);
  }

  function scanMemory(v, toks, mem, add) {
    if (!mem || !mem.entries.length) return;
    var splitCue = toks.some(function (t) { return L.SPLIT_WORDS[t.low]; });
    toks.forEach(function (t, idx) {
      var c = compact(t.raw);
      if (c.length < 3) return;
      var rev = c.split("").reverse().join("");
      for (var i = 0; i < mem.entries.length; i++) {
        var e = mem.entries[i];
        var secretish = e.cat !== "NAME" && e.cat !== "ADDRESS" && e.cat !== "TERM";
        if (c === e.c) {
          add({ a: t.a, b: t.b, cat: e.cat, level: "high", layer: "memory", ph: e.ph,
                ev: "Masked earlier in this conversation" });
          return;
        }
        if (secretish && rev === e.c && c.length >= 4) {
          add({ a: t.a, b: t.b, cat: e.cat, level: "high", layer: "memory", ph: e.ph,
                ev: "An earlier secret, written backwards" });
          return;
        }
        if (secretish && e.c.length >= 5) {
          if (c.indexOf(e.c) !== -1 && c.length <= e.c.length + 6) {
            add({ a: t.a, b: t.b, cat: e.cat, level: "high", layer: "memory", ph: e.ph,
                  ev: "Contains an earlier secret" });
            return;
          }
          var ordinary = isCommon(t.low) || L.COMMON_PASSWORDS[t.low] || cueAt([t], 0);
          if (!ordinary && e.c.indexOf(c) !== -1 &&
              ((splitCue && c.length >= 3) || (c.length >= 5 && c.length >= e.c.length * 0.6))) {
            add({ a: t.a, b: t.b, cat: e.cat, level: splitCue ? "high" : "medium",
                  layer: "memory", ph: e.ph, ev: "Part of an earlier secret" });
            return;
          }
        }
      }
    });
    /* An earlier secret split across neighbouring tokens: "adi 123". */
    for (var i = 0; i + 1 < toks.length; i++) {
      var pair = compact(toks[i].raw + toks[i + 1].raw);
      var tri = toks[i + 2] ? compact(toks[i].raw + toks[i + 1].raw + toks[i + 2].raw) : "";
      mem.entries.forEach(function (e) {
        if (e.cat === "NAME" || e.cat === "ADDRESS" || e.c.length < 5) return;
        if (pair === e.c) add({ a: toks[i].a, b: toks[i + 1].b, cat: e.cat, level: "high", layer: "memory",
                                ph: e.ph, ev: "An earlier secret, split in two" });
        else if (tri === e.c) add({ a: toks[i].a, b: toks[i + 2].b, cat: e.cat, level: "high", layer: "memory",
                                    ph: e.ph, ev: "An earlier secret, split in three" });
      });
    }
  }

  /* ----------------------------------------------------------------- rules */

  var ENTITY_CATS = {
    NAME: ["NAME"], ADDR: ["ADDRESS", "PLACE", "POSTAL"], PLACE: ["PLACE", "ADDRESS"], ORG: ["ORG"],
    EMAIL: ["EMAIL"], PHONE: ["PHONE"], DOB: ["DOB"], DATE: ["DATE", "DOB"], AGE: ["AGE"],
    ID: ["ID", "ACCOUNT", "AADHAAR", "PAN", "PASSPORT", "UPI", "CARD"], ACCOUNT: ["ACCOUNT", "UPI", "CARD"],
    SECRET: ["SECRET", "PIN", "OTP", "CVV", "CREDENTIAL"], USERNAME: ["USERNAME"], URL: ["URL"],
    IP: ["IP"], SALARY: ["FINANCIAL"], MONEY: ["FINANCIAL"], NUMBER: [], HEALTH: ["HEALTH"],
    BELIEF: ["BELIEF"], SEXUALITY: ["SEXUALITY"], LEGAL: ["LEGAL"]
  };

  var ENTITY_RE = {
    MONEY:  /(?:\u20b9|Rs\.?|INR|\$|\u20ac|\u00a3)\s?[\d,]+(?:\.\d{1,2})?(?:\s?(?:k|lakhs?|lacs?|crores?|cr|lpa|million|m|bn))?|\b\d[\d,.]*\s?(?:lakhs?|lacs?|crores?|cr|lpa|k)\b|\b\d{1,3}(?:,\d{2,3})+(?:\.\d{1,2})?\b/gi,
    SALARY: /(?:\u20b9|Rs\.?|INR|\$|\u20ac|\u00a3)\s?[\d,]+(?:\.\d{1,2})?(?:\s?(?:k|lakhs?|lacs?|crores?|cr|lpa))?|\b\d[\d,.]*\s?(?:lakhs?|lacs?|crores?|cr|lpa|k)\b|\b\d{4,}\b/gi,
    NUMBER: /\b\d[\d,.]*\b/g,
    URL:    /\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi
  };

  function scanRules(v, rules, add) {
    var s = v.s, forced = {}, topics = {};
    (rules || []).forEach(function (r) {
      if (r.kind === "term" && r.value) {
        var term = String(r.value).trim();
        if (!term) return;
        var wordy = /^[\p{L}\p{N}]/u.test(term) && /[\p{L}\p{N}]$/u.test(term);
        var re = new RegExp((wordy ? "(?<![\\p{L}\\p{N}])" : "") +
                            term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+") +
                            (wordy ? "(?:'s)?(?![\\p{L}\\p{N}])" : ""), "giu");
        var m;
        while ((m = re.exec(s)) !== null) {
          add({ a: m.index, b: m.index + m[0].length, cat: "TERM", level: "high", layer: "rule",
                ev: 'Your rule: hide "' + term + '"' });
        }
      } else if (r.kind === "entity") {
        (ENTITY_CATS[r.entity] || []).forEach(function (c) { forced[c] = r; });
        if (L.TOPICS[r.entity]) topics[r.entity] = true;
        var re2 = ENTITY_RE[r.entity];
        if (re2) {
          re2.lastIndex = 0;
          var m2;
          while ((m2 = re2.exec(s)) !== null) {
            add({ a: m2.index, b: m2.index + m2[0].length,
                  cat: r.entity === "NUMBER" ? "NUMBER" : r.entity === "URL" ? "URL" : "FINANCIAL",
                  level: "high", layer: "rule", ev: "Your rule: " + (r.label || r.entity.toLowerCase()) });
          }
        }
      }
    });
    return { forced: forced, topics: topics };
  }

  /* ---------------------------------------------------------- placeholders */

  var PH = {
    PIN: "[PIN]", OTP: "[OTP]", CVV: "[CVV]", CREDENTIAL: "[CREDENTIAL]", USERNAME: "[USERNAME]",
    ACCOUNT: "[ACCOUNT_NUMBER]", UPI: "[UPI_ID]", ID: "[ID_NUMBER]", DOB: "[DOB]", DATE: "[DATE]",
    AGE: "[AGE]", FINANCIAL: "[AMOUNT]", POSTAL: "[PIN_CODE]", IP: "[IP_ADDRESS]",
    COORD: "[COORDINATES]", EMAIL: "[EMAIL]", PHONE: "[PHONE]", CARD: "[CARD]", AADHAAR: "[AADHAAR]",
    ENCODED: "[ENCODED_SECRET]", TERM: "[HIDDEN]", HEALTH: "[HEALTH_INFO]", BELIEF: "[BELIEF]",
    SEXUALITY: "[IDENTITY]", LEGAL: "[LEGAL_INFO]", URL: "[URL]", NUMBER: "[NUMBER]"
  };
  var NUMBERED = { NAME: "PERSON", ADDRESS: "ADDRESS", PLACE: "PLACE", ORG: "ORG" };

  function placeholderFor(mem, item) {
    if (item.ph) return item.ph;
    if (item.cat === "SECRET") return D.describeSecret(item.value);
    var base = NUMBERED[item.cat];
    if (!base) return PH[item.cat] || "[" + item.cat + "]";
    var store = mem;
    var key = item.cat + ":" + compact(item.value);
    if (!store.numbers[key]) {
      /* "Vilas" after "Vilas Rakhe" is the same person. */
      if (item.cat === "NAME" && mem.entries) {
        var hit = mem.entries.filter(function (e) { return e.cat === "NAME" && e.c === compact(item.value); })[0];
        if (hit) return hit.ph;
      }
      store.counters[base] = (store.counters[base] || 0) + 1;
      store.numbers[key] = "[" + base + "_" + store.counters[base] + "]";
    }
    return store.numbers[key];
  }

  /* ---------------------------------------------------------------- kinds */

  var KIND = {
    SECRET: "Password or secret", CREDENTIAL: "Credential", PIN: "PIN or code", OTP: "One-time code",
    CVV: "Card security code", USERNAME: "Username", ACCOUNT: "Account number", UPI: "UPI ID",
    ID: "ID number", NAME: "Person's name", ADDRESS: "Postal address", PLACE: "Place",
    ORG: "Organisation", DOB: "Date of birth", DATE: "Date", AGE: "Age", FINANCIAL: "Amount of money",
    POSTAL: "PIN code", IP: "Network address", COORD: "Location coordinates", EMAIL: "Email address",
    PHONE: "Phone number", CARD: "Card number", AADHAAR: "Aadhaar number", ENCODED: "Encoded secret",
    TERM: "Your hidden term", HEALTH: "Health information", BELIEF: "Religion or belief",
    SEXUALITY: "Sexual orientation", LEGAL: "Legal matter", URL: "Link", NUMBER: "Number",
    NRP: "Nationality or religion"
  };

  var DETECT_CAT = {
    "Payment card": "CARD", "Aadhaar number": "AADHAAR", "PAN": "PAN", "Bank IFSC": "ACCOUNT",
    "Passport number": "PASSPORT", "Vehicle registration": "VEHICLE", "Mobile number": "PHONE",
    "Email address": "EMAIL", "Date of birth": "DOB", "Masked secret": "SECRET",
    "Password in message": "SECRET", "One-time code": "OTP", "PIN in message": "PIN",
    "Card security code": "CVV", "Credential in message": "CREDENTIAL", "API key": "CREDENTIAL",
    "Credential-like string": "CREDENTIAL", "ID number (read from image)": "ID"
  };

  /* ---------------------------------------------------------------- analyse */

  /**
   * text     the input
   * opts.ner      spans from the personal-data model, in text offsets
   * opts.memory   a memory object (see createMemory), read and extended
   * opts.rules    the user's rules
   * opts.allow    terms never to flag
   * opts.ocr      text read from a picture: numbers are not held to checksums
   * opts.source   "chat", "file", "screen", "ocr" -- recorded on findings
   */
  function analyze(text, opts) {
    opts = opts || {};
    text = String(text == null ? "" : text);
    var v = makeView(text);
    var toks = tokenize(v.s);
    var cands = [], warnings = [];

    function add(c) {
      if (c.b <= c.a) return;
      cands.push(c);
    }
    function warn(w) {
      w.startView = w.start; w.endView = w.end;
      var dup = warnings.some(function (x) {
        return x.type === w.type && x.topic === w.topic && w.start < x.endView && w.end > x.startView;
      });
      if (!dup) warnings.push(w);
    }

    /* the model's spans are in original offsets; move them into the view */
    var nerView = [];
    if (opts.ner && opts.ner.length) {
      var back = new Array(text.length + 1);
      for (var q = v.from.length - 1; q >= 0; q--) back[v.from[q]] = q;
      for (var z = text.length; z >= 0; z--) if (back[z] === undefined) back[z] = z < text.length ? back[z + 1] : v.s.length;
      opts.ner.forEach(function (n) {
        var a = back[n.start], b = n.end >= text.length ? v.s.length : back[n.end];
        if (a !== undefined && b !== undefined && b > a) {
          nerView.push({ a: a, b: b, label: n.label, score: n.score });
        }
      });
    }

    /* 2. detectors */
    D.scan(v.s, { ocr: !!opts.ocr }).forEach(function (h) {
      var cat = DETECT_CAT[h.kind] || "ID";
      /* The date pattern matches every date. Only one near a birth cue is a
         date of birth; a meeting date is not private. */
      if (cat === "DOB" && !contextOf(v.s, h.start).birth &&
          !/\b(dob|d\.o\.b|birth|born|birthday)\b/i.test(v.s.slice(Math.max(0, h.start - 30), h.start))) {
        add({ a: h.start, b: h.end, cat: "DATE", level: "low", layer: "detector", kind: "Date",
              ev: "A date, with nothing saying it is a birth date" });
        return;
      }
      add({ a: h.start, b: h.end, cat: cat, level: "high", layer: "detector",
            ph: h.ph, kind: h.kind, ev: h.ev });
    });

    /* 3-7 */
    scanCues(v, toks, add, warn);
    scanStructure(v, add);
    scanPeople(v, toks, add);
    scanAddresses(v, add, nerView);
    scanModel(v, nerView, add, warn, toks);
    scanShape(v, toks, add, opts.inner ? null : function (inner) {
      return analyze(inner, { inner: true, memory: opts.memory }).items;
    });

    /* backwards: "321ida si drowssap ym" */
    if (!opts.inner && toks.length >= 3) {
      var rv = v.s.split("").reverse().join("");
      var rtoks = tokenize(rv);
      var rc = [];
      scanCues({ s: rv }, rtoks, function (c) { if (LEVELS[c.level] >= 2) rc.push(c); }, function () {});
      rc.forEach(function (c) {
        add({ a: v.s.length - c.b, b: v.s.length - c.a, cat: c.cat, level: "high", layer: "cue",
              ev: "Written backwards: " + c.ev.toLowerCase() });
      });
    }

    /* 8 */
    scanMemory(v, toks, opts.memory, add);

    /* rules */
    var ruled = scanRules(v, opts.rules, add);
    scanTopics(v, toks, warn, add, ruled.topics);

    /* entity rules lift whole categories to certain */
    cands.forEach(function (c) {
      if (ruled.forced[c.cat] && c.level !== "high") {
        c.level = "high";
        c.ev += "; your rule: " + (ruled.forced[c.cat].label || ruled.forced[c.cat].entity.toLowerCase());
      }
    });

    /* allowlist: what the user said is fine */
    var allow = (opts.allow || []).concat(opts.memory ? opts.memory.allow : [])
      .map(function (x) { return compact(x); }).filter(Boolean);
    (opts.rules || []).forEach(function (r) { if (r.kind === "allow" && r.value) allow.push(compact(r.value)); });

    /* reconcile: strongest level wins, then the most specific layer, then
       the longest span */
    var ORDER = { rule: 0, structure: 1, detector: 2, memory: 3, cue: 4, address: 5, people: 6, model: 7, shape: 8 };
    cands.forEach(function (c) { c.value = c.val || v.s.slice(c.a, c.b); });
    cands = cands.filter(function (c) {
      return c.value.trim() && allow.indexOf(compact(c.value)) === -1;
    });
    cands.sort(function (x, y) {
      return (LEVELS[y.level] - LEVELS[x.level]) || (ORDER[x.layer] - ORDER[y.layer]) ||
             ((y.b - y.a) - (x.b - x.a)) || (x.a - y.a);
    });
    var kept = [];
    cands.forEach(function (c) {
      var clash = kept.some(function (k) { return c.a < k.b && c.b > k.a; });
      if (clash) {
        /* A wider finding that swallows a stronger one is still useful when it
           is an address around a PIN code, for instance: extend, don't drop. */
        return;
      }
      kept.push(c);
    });
    kept.sort(function (x, y) { return x.a - y.a; });
    /* "aadhaar: 4295 3718 2644" -- the key found it, the checksum names it. */
    kept.forEach(function (k) {
      if (k.layer !== "structure") return;
      var same = cands.filter(function (c) { return c.layer === "detector" && c.a === k.a && c.b === k.b; })[0];
      if (same) { k.cat = same.cat; k.ph = same.ph; k.kind = same.kind; }
    });

    /* Numbered placeholders need one counter per call at least, so two
       addresses in one document are [ADDRESS_1] and [ADDRESS_2]. */
    var numbering = opts.memory || { entries: [], counters: {}, numbers: {} };
    var items = kept.map(function (c) {
      var o = origSpan(v, c.a, c.b);
      var item = {
        start: o.start, end: o.end, match: text.slice(o.start, o.end), value: c.value,
        cat: c.cat, kind: c.kind || KIND[c.cat] || c.cat, level: c.level, layer: c.layer,
        ev: c.ev, score: c.score
      };
      item.ph = placeholderFor(numbering, Object.assign({ ph: c.ph }, item));
      return item;
    });

    var warns = warnings.map(function (w) {
      var o = origSpan(v, w.startView, w.endView) || { start: 0, end: 0 };
      return { type: w.type, topic: w.topic, why: w.why, start: o.start, end: o.end,
               text: text.slice(o.start, o.end) };
    });

    return { items: items, warnings: warns };
  }

  /* Replaces the chosen findings with their placeholders. `masked` decides per
     item; by default high and medium findings are masked. */
  function apply(text, items, masked) {
    var out = "", cur = 0;
    items.slice().sort(function (a, b) { return a.start - b.start; }).forEach(function (it, i) {
      var on = masked ? masked(it, i) : LEVELS[it.level] >= 2;
      if (!on || it.start < cur) return;
      out += text.slice(cur, it.start) + it.ph;
      cur = it.end;
    });
    return out + text.slice(cur);
  }

  function commit(mem, items, masked) {
    if (!mem) return;
    items.forEach(function (it, i) {
      var on = masked ? masked(it, i) : LEVELS[it.level] >= 2;
      if (on) remember(mem, it);
    });
  }

  /**
   * The last check before anything leaves: structured values the detectors
   * are sure of, secrets named by a key, and anything masked earlier in the
   * conversation. Returns what it found; the caller refuses to send if the
   * list is not empty.
   */
  function exitCheck(payload, mem) {
    var found = [];
    D.scan(payload).forEach(function (h) { found.push(h.kind); });
    var v = makeView(payload);
    scanStructure(v, function (c) {
      var val = v.s.slice(c.a, c.b);
      if (!isPlaceholder(val) && (c.cat === "SECRET" || c.cat === "CREDENTIAL")) found.push(KIND[c.cat]);
    });
    if (mem) {
      var toks = tokenize(v.s);
      toks.forEach(function (t) {
        var c = compact(t.raw);
        if (c.length < 4) return;
        mem.entries.forEach(function (e) {
          if (e.cat !== "NAME" && e.cat !== "ADDRESS" && e.cat !== "TERM" && !e.part && e.c === c) {
            found.push(KIND[e.cat] || e.cat);
          }
        });
      });
    }
    return found;
  }

  return {
    analyze: analyze, apply: apply, commit: commit, exitCheck: exitCheck,
    createMemory: createMemory, remember: remember, LEVELS: LEVELS, KIND: KIND,
    ENTITY_RE: ENTITY_RE, _internal: { tokenize: tokenize, makeView: makeView, secretShape: secretShape,
                                       valueFor: valueFor, contextOf: contextOf }
  };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueGuard;
