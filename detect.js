/* Opaque -- shared detection rules.
 *
 * Loaded as a classic script in both the content script and the side panel,
 * so it defines a single global rather than using module syntax.
 *
 * Tier 1 is deterministic: checksums and formats. No model, no guessing.
 * A twelve digit number that satisfies the Verhoeff check is an Aadhaar number
 * with near certainty, and that costs microseconds instead of an inference pass.
 */
var OpaqueDetect = (function () {
  "use strict";

  /* ---------- Verhoeff, used by Aadhaar ---------- */
  var D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
  ];
  var P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
  ];

  function verhoeff(s) {
    var d = s.replace(/\D/g, "");
    if (d.length !== 12) return false;
    var c = 0;
    for (var i = d.length - 1, n = 0; i >= 0; i--, n++) {
      c = D[c][P[n % 8][+d[i]]];
    }
    return c === 0;
  }

  /* ---------- Luhn, used by payment cards ---------- */
  function luhn(s) {
    var d = s.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19) return false;
    var sum = 0, alt = false;
    for (var i = d.length - 1; i >= 0; i--) {
      var v = +d[i];
      if (alt) { v *= 2; if (v > 9) v -= 9; }
      sum += v; alt = !alt;
    }
    return sum % 10 === 0;
  }

  /* ---------- rule table ----------
   * Ordered most-specific first, because a card number would otherwise be
   * partially swallowed by the looser numeric patterns.
   */
  var RULES = [
    { kind: "Payment card", ph: "[CARD]", tier: 1, severity: "high",
      ev: "Luhn checksum passes",
      re: /\b\d(?:[ -]?\d){12,18}\b/g, verify: luhn },

    { kind: "Aadhaar number", ph: "[AADHAAR]", tier: 1, severity: "high",
      ev: "Verhoeff checksum passes",
      re: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, verify: verhoeff },

    { kind: "PAN", ph: "[PAN]", tier: 1, severity: "high",
      ev: "PAN format (AAAAA9999A)",
      re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, verify: function () { return true; } },

    { kind: "Bank IFSC", ph: "[IFSC]", tier: 1, severity: "high",
      ev: "IFSC format (AAAA0XXXXXX)",
      re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, verify: function () { return true; } },

    { kind: "Passport number", ph: "[PASSPORT]", tier: 1, severity: "high",
      ev: "Indian passport format",
      re: /\b[A-PR-WY][0-9]{7}\b/g, verify: function () { return true; } },

    { kind: "Vehicle registration", ph: "[VEHICLE]", tier: 1, severity: "medium",
      ev: "Indian registration format",
      re: /\b[A-Z]{2}[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b/g,
      verify: function () { return true; } },

    { kind: "Mobile number", ph: "[PHONE]", tier: 1, severity: "high",
      ev: "Indian mobile format",
      re: /(?:\+?91[ -]?)?\b[6-9]\d{4}[ -]?\d{5}\b/g,
      verify: function (t) { return t.replace(/\D/g, "").length <= 12; } },

    { kind: "Email address", ph: "[EMAIL]", tier: 1, severity: "medium",
      ev: "Email format",
      re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      verify: function () { return true; } },

    { kind: "Date of birth", ph: "[DOB]", tier: 1, severity: "medium",
      ev: "Date pattern",
      re: /\b(?:0?[1-9]|[12]\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19|20)\d{2}\b/g,
      verify: function () { return true; } },

    { kind: "Masked secret", ph: "[SECRET]", tier: 1, severity: "high",
      ev: "Masked input glyphs",
      re: /[\u2022\u00b7*]{4,}/g, verify: function () { return true; } }
  ];

  /* ---------- text that was read out of a picture ----------
   * A checksum is proof for typed text and the wrong test for OCR output: one
   * misread digit turns a real Aadhaar into a number that fails Verhoeff, and
   * the value leaks precisely because the reader was imperfect. So text from an
   * image also gets a shape-only rule. Anything grouped the way ID numbers are
   * printed -- 4-4-4, 4-4-4-4, or one group a digit short -- is covered, and so
   * is a long unbroken run of digits. Over-covering a number on an ID card is
   * cheap; missing one is not.
   */
  var OCR_RULES = [
    { kind: "ID number (read from image)", ph: "[ID_NUMBER]", tier: 2, severity: "high",
      ev: "grouped like an Aadhaar, VID or card number; a checksum cannot be trusted after OCR",
      re: /\b\d{3,4}(?:[ -]\d{3,4}){2,3}\b|\b\d{11,16}\b/g,
      verify: function () { return true; } }
  ];

  /* ---------- secrets that have no shape ----------
   *
   * An Aadhaar number has a checksum. A password has nothing: "adi@123",
   * "hunter2" and "adjhfb124" share no pattern, so nothing about the value
   * itself proves it is a secret.
   *
   * What gives it away is the word next to it. That was the first approach, and
   * it broke the moment someone typed "oassword" -- an exact keyword match is
   * brittle in exactly the situation where a leak matters most.
   *
   * So two independent signals are combined instead. A trigger word is matched
   * approximately, surviving typos, leetspeak and odd spacing. The candidate
   * value is scored on its own properties: character classes, length, entropy,
   * whether it looks like an ordinary English word. Neither signal needs to be
   * perfect, because a weak trigger next to a strong-looking value still crosses
   * the line, and a strong trigger will pull through a modest-looking value.
   */

  var TRIGGERS = [
    /* word,            placeholder,    weight */
    ["password",        "SECRET",       1.00],
    ["passwd",          "SECRET",       1.00],
    ["passphrase",      "SECRET",       1.00],
    ["passcode",        "SECRET",       0.95],
    ["pwd",             "SECRET",       0.90],
    ["mypassword",      "SECRET",       1.00],
    ["otp",             "OTP",          0.95],
    ["onetimepassword", "OTP",          1.00],
    ["verificationcode","OTP",          1.00],
    ["authcode",        "OTP",          0.95],
    ["cvv",             "CVV",          0.95],
    ["cvc",             "CVV",          0.95],
    ["securitycode",    "CVV",          0.90],
    ["pin",             "PIN",          0.80],
    ["apikey",          "CREDENTIAL",   1.00],
    ["accesskey",       "CREDENTIAL",   1.00],
    ["privatekey",      "CREDENTIAL",   1.00],
    ["secretkey",       "CREDENTIAL",   1.00],
    ["token",           "CREDENTIAL",   0.75],
    ["secret",          "CREDENTIAL",   0.75],
    ["credential",      "CREDENTIAL",   0.80],
    ["credentials",     "CREDENTIAL",   0.80]
  ];

  /* Words that sit between a trigger and its value and carry no meaning here. */
  var CONNECTORS = ["is", "are", "was", "to", "as", "be", "will", "would", "the",
                    "my", "a", "an", "of", "for", "into", "it", "now", "then",
                    "should", "shall", "can", "could", "set", "change", "changed",
                    "update", "updated", "reset", "make", "making", "use", "using",
                    "new", "old", "current", "chosen", "keep", "keeping", "and"];

  /* Ordinary words that follow a trigger but are never the secret itself. */
  var NOT_VALUES = ["something", "anything", "stronger", "strong", "secure",
                    "better", "safe", "safer", "complex", "simple", "short",
                    "long", "longer", "here", "there", "empty", "blank", "field",
                    "box", "again", "please", "help", "correct", "wrong", "valid",
                    "invalid", "required", "optional", "hidden", "visible",
                    "reset", "change", "expired", "incorrect", "manager",
                    "protected", "policy", "rules", "requirements", "same",
                    "different", "anything", "nothing", "one", "this", "that"];

  /* Leetspeak folded back to letters, so p@ssw0rd reads as password. */
  var LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
               "8": "b", "@": "a", "$": "s", "!": "i", "|": "l" };

  function normalizeWord(w) {
    var out = "";
    for (var i = 0; i < w.length; i++) {
      var ch = w[i].toLowerCase();
      if (LEET[ch]) ch = LEET[ch];
      if (ch >= "a" && ch <= "z") out += ch;
    }
    return out;
  }

  /* Levenshtein with an early exit, so long words do not cost anything. */
  function editDistance(a, b, cap) {
    if (Math.abs(a.length - b.length) > cap) return cap + 1;
    var prev = [], cur = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      cur[0] = i;
      var best = cur[0];
      for (j = 1; j <= b.length; j++) {
        var cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
        if (cur[j] < best) best = cur[j];
      }
      if (best > cap) return cap + 1;
      for (j = 0; j <= b.length; j++) prev[j] = cur[j];
    }
    return prev[b.length];
  }

  /* Real words one or two letters away from a trigger. "passport" is not a
     misspelt "password". */
  var NEAR_MISSES = ["passport", "passports", "mypassport", "passage", "passenger", "passengers",
                     "passing", "compass", "bypass", "surpass", "mypassage", "pasword"];

  /* How strongly a word signals "a secret follows". 0 means no signal. */
  function triggerScore(word) {
    var n = normalizeWord(word);
    if (n.length < 3) return null;
    if (NEAR_MISSES.indexOf(n) !== -1 && n !== "pasword") return null;
    var best = null;
    for (var i = 0; i < TRIGGERS.length; i++) {
      var t = TRIGGERS[i], target = t[0];
      if (n === target) {
        return { ph: t[1], score: t[2], word: target, exact: true };
      }
      /* Allow one typo in medium words, two in long ones. "oassword" is one
         substitution from "password"; "passwrd" is one deletion. */
      var cap = target.length >= 8 ? 2 : (target.length >= 5 ? 1 : 0);
      if (cap === 0) continue;
      var d = editDistance(n, target, cap);
      if (d <= cap) {
        var penalty = 1 - (d * 0.18);
        var s = t[2] * penalty;
        if (!best || s > best.score) {
          best = { ph: t[1], score: s, word: target, exact: false, dist: d };
        }
      }
    }
    return best;
  }

  /* Shannon entropy per character. Random strings score high, words low. */
  function entropyPerChar(s) {
    var freq = {}, i;
    for (i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var h = 0;
    for (var k in freq) {
      var p = freq[k] / s.length;
      h -= p * (Math.log(p) / Math.log(2));
    }
    return h;
  }

  /* How much this looks like a credential rather than an ordinary word. 0 to 1. */
  function credentialScore(v, numericHint) {
    if (!v) return 0;
    if (/^\[[A-Z_]/.test(v)) return 0;                 // our own placeholder
    if (/^[A-Z_]{4,}$/.test(v)) return 0;              // a bare tag or acronym
    /* Three characters is normally far too short to be anything, but a CVV is
       exactly three digits, so the trigger relaxes the floor. */
    if (v.length > 128) return 0;
    if (v.length < (numericHint ? 3 : 4)) return 0;
    if (NOT_VALUES.indexOf(v.toLowerCase()) !== -1) return 0;
    if (CONNECTORS.indexOf(v.toLowerCase()) !== -1) return 0;
    if (/^https?:\/\//i.test(v)) return 0;
    if (/^[a-z]+['\u2019](s|t|re|ve|ll|d|m)$/i.test(v)) return 0;   // "dog's", "didn't" -- words
    if (/@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) return 0;   // an email

    var s = 0;
    var hasLower = /[a-z]/.test(v), hasUpper = /[A-Z]/.test(v);
    var hasDigit = /\d/.test(v), hasSym = /[^A-Za-z0-9]/.test(v);

    if (hasDigit && (hasLower || hasUpper)) s += 0.40;
    if (hasSym) s += 0.25;
    if (hasLower && hasUpper) s += 0.20;
    if (v.length >= 8) s += 0.15;
    if (v.length >= 12) s += 0.15;
    if (entropyPerChar(v) > 2.9) s += 0.20;
    /* A short run of digits means nothing by itself -- "page 834" is not a
       secret. After a CVV, PIN or OTP trigger it means everything. */
    if (/^\d+$/.test(v)) {
      if (numericHint && v.length >= 3 && v.length <= 8) s += 0.75;
      else if (v.length >= 4 && v.length <= 8) s += 0.45;
    }
    if (/^[a-z]+$/.test(v) && v.length <= 10) s -= 0.35;   // probably just a word

    return Math.max(0, Math.min(1, s));
  }

  function describeSecret(v) {
    var bits = [v.length + " chars"];
    var classes = [];
    if (/[a-z]/.test(v)) classes.push("lowercase");
    if (/[A-Z]/.test(v)) classes.push("uppercase");
    if (/\d/.test(v)) classes.push("digits");
    if (/[^A-Za-z0-9]/.test(v)) classes.push("symbols");
    bits.push(classes.length ? classes.join("+") : "unknown charset");

    var weak = [];
    if (/^\D+\d+$/.test(v)) weak.push("letters then digits");
    if (/(19|20)\d{2}$/.test(v)) weak.push("ends with a year");
    if (/^(.)\1+$/.test(v)) weak.push("one repeated character");
    if (/012|123|234|345|456|567|678|789|890/.test(v)) weak.push("sequential digits");
    if (/^[a-z]+$/.test(v)) weak.push("lowercase letters only");
    if (/(qwerty|asdf|zxcv|password|admin|welcome|letmein|iloveyou|abc123)/i.test(v)) {
      weak.push("contains a very common pattern");
    }
    if (v.length < 8) weak.push("shorter than 8 characters");
    if (entropyPerChar(v) < 2.2) weak.push("low variety of characters");
    if (weak.length) bits.push(weak.join(", "));
    else bits.push("no obvious weakness");

    return "[SECRET: " + bits.join("; ") + "]";
  }

  /* Credentials that betray themselves by shape, needing no trigger at all. */
  var KEY_SHAPES = [
    { kind: "API key", ph: "[API_KEY]", ev: "Known key prefix",
      re: /\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{30,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{12,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g }
  ];

  /* Splits text into words while remembering where each one started. */
  function tokenize(text) {
    var toks = [], re = /\S+/g, m;
    while ((m = re.exec(text)) !== null) {
      var raw = m[0];
      var lead = raw.match(/^[^A-Za-z0-9@#$!*_+\-\[]*/)[0].length;
      var core = raw.slice(lead);
      /* Keep a trailing "]" when the token opens with "[", so an inserted
         placeholder survives tokenising intact and can be recognised as ours. */
      core = /^\[/.test(core) ? core.replace(/[),.;:!?'"`]+$/, "")
                              : core.replace(/[)\]}>,.;:!?'"`]+$/, "");
      if (core) toks.push({ raw: core, start: m.index + lead });
    }
    return toks;
  }

  function scanContext(text) {
    var hits = [];
    var toks = tokenize(text);

    for (var i = 0; i < toks.length; i++) {
      /* Triggers can be written as several words -- "pass word", "api key",
         "one time password". Try joining up to three tokens and keep whichever
         reading is strongest. */
      var trig = null, span = 1;
      for (var n = 1; n <= 3 && i + n <= toks.length; n++) {
        var joined = "";
        for (var k = 0; k < n; k++) joined += toks[i + k].raw;
        var t = triggerScore(joined);
        if (t && (!trig || t.score > trig.score)) { trig = t; span = n; }
      }
      if (!trig) continue;

      var numericHint = (trig.ph === "CVV" || trig.ph === "PIN" || trig.ph === "OTP");

      /* Walk forward past connectors and separators to the first real candidate. */
      for (var j = i + span, skipped = 0; j < toks.length && skipped <= 4; j++) {
        var cand = toks[j].raw.replace(/^[:=]+/, "").replace(/[:=]+$/, "");
        if (!cand) { skipped++; continue; }
        var low = cand.toLowerCase();
        if (CONNECTORS.indexOf(low) !== -1) { skipped++; continue; }

        var cscore = credentialScore(cand, numericHint);
        /* A confident trigger accepts a weaker-looking value, and vice versa. */
        var combined = trig.score * 0.55 + cscore * 0.45;
        if (combined >= 0.42 && cscore > 0) {
          hits.push({
            start: toks[j].start, end: toks[j].start + cand.length, match: cand,
            kind: trig.ph === "SECRET" ? "Password in message"
                : trig.ph === "OTP" ? "One-time code"
                : trig.ph === "PIN" ? "PIN in message"
                : trig.ph === "CVV" ? "Card security code"
                : "Credential in message",
            ph: trig.ph === "SECRET" ? describeSecret(cand) : "[" + trig.ph + "]",
            ev: trig.exact
              ? 'Follows "' + trig.word + '"'
              : 'Follows "' + toks[i].raw + '", read as "' + trig.word + '"' +
                (trig.dist ? " (" + trig.dist + " character difference)" : ""),
            tier: 1, severity: "high"
          });
        }
        break;                       // only the first candidate after a trigger
      }
    }

    KEY_SHAPES.forEach(function (r) {
      r.re.lastIndex = 0;
      var m;
      while ((m = r.re.exec(text)) !== null) {
        hits.push({ start: m.index, end: m.index + m[0].length, match: m[0],
                    kind: r.kind, ph: r.ph, ev: r.ev, tier: 1, severity: "high" });
      }
    });

    /* Long high-entropy strings are credentials whatever the sentence says. */
    toks.forEach(function (t) {
      var v = t.raw;
      if (v.length < 20 || v.length > 128) return;
      if (/^\[[A-Z_]/.test(v)) return;
      if (/^https?:\/\//i.test(v) || /\.[a-z]{2,4}$/i.test(v)) return;
      if (!/\d/.test(v) || !/[A-Za-z]/.test(v)) return;
      if (entropyPerChar(v) < 3.6) return;
      hits.push({ start: t.start, end: t.start + v.length, match: v,
                  kind: "Credential-like string", ph: "[CREDENTIAL]",
                  ev: "Long, high-entropy, mixed characters",
                  tier: 1, severity: "high" });
    });

    /* One value can satisfy several rules; keep the widest span once. */
    hits.sort(function (a, b) {
      return a.start - b.start || (b.end - b.start) - (a.end - a.start);
    });
    var kept = [];
    hits.forEach(function (h) {
      if (!kept.some(function (k) { return h.start < k.end && h.end > k.start; })) {
        kept.push(h);
      }
    });
    return kept;
  }


  /* Returns every sensitive span inside a string, with offsets, so the caller
   * can highlight exactly the value rather than the whole line. Overlapping
   * matches are resolved in favour of whichever rule matched first. */
  function scan(text, opts) {
    if (!text) return [];
    /* Context rules run first and win ties: if a value is both a plausible
       pattern and an announced secret, the secret reading is the safer one. */
    var hits = scanContext(text);
    /* OCR rules run last, so a number that does pass its checksum keeps its
       precise label. */
    var rules = opts && opts.ocr ? RULES.concat(OCR_RULES) : RULES;
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      r.re.lastIndex = 0;
      var m;
      while ((m = r.re.exec(text)) !== null) {
        if (!m[0].trim()) continue;
        if (!r.verify(m[0])) continue;
        var start = m.index, end = m.index + m[0].length;
        var clash = false;
        for (var j = 0; j < hits.length; j++) {
          if (start < hits[j].end && end > hits[j].start) { clash = true; break; }
        }
        if (clash) continue;
        hits.push({
          start: start, end: end, match: m[0],
          kind: r.kind, ph: r.ph, ev: r.ev, tier: r.tier, severity: r.severity
        });
      }
    }
    return hits.sort(function (a, b) { return a.start - b.start; });
  }

  /* Replaces every sensitive span with its placeholder, keeping the rest. */
  function redactText(text, opts) {
    var hits = scan(text, opts);
    if (!hits.length) return text;
    var out = "", cursor = 0;
    for (var i = 0; i < hits.length; i++) {
      out += text.slice(cursor, hits[i].start) + hits[i].ph;
      cursor = hits[i].end;
    }
    return out + text.slice(cursor);
  }

  return { scan: scan, redactText: redactText, RULES: RULES,
           verhoeff: verhoeff, luhn: luhn, editDistance: editDistance,
           describeSecret: describeSecret, entropyPerChar: entropyPerChar,
           triggerScore: triggerScore, normalizeWord: normalizeWord };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueDetect;
