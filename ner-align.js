/* Opaque -- maps the text model's output back onto the original text.
 *
 * The personal-data model reads word pieces, not characters: "Vilas Rakhe"
 * arrives as vila, ##s, ra, ##kh, ##e, each with a label. To cover the name on
 * the page, or replace it in a message, those labels have to become character
 * offsets in the text the user actually wrote.
 *
 * The model's tokenizer lowercases and strips accents first, then splits on
 * whitespace and punctuation. So the same view of the text is rebuilt here,
 * remembering which original character each normalised character came from,
 * and the pieces are walked through it in order.
 *
 * Shared by the sandboxed worker, which runs the model, and by the tests.
 */
var OpaqueNer = (function () {
  "use strict";

  var PUNCT = /[!-\/:-@\[-`{-~]|\p{P}/u;
  var MARK = /\p{Mn}/gu;
  var SPACE = /\s/;

  function normalizedView(text) {
    var norm = "", from = [], to = [];
    for (var i = 0; i < text.length;) {
      var cp = text.codePointAt(i);
      var len = cp > 0xffff ? 2 : 1;
      var d = text.substr(i, len).normalize("NFD").replace(MARK, "").toLowerCase();
      for (var k = 0; k < d.length; k++) {
        norm += d[k];
        from.push(i);
        to.push(i + len);
      }
      i += len;
    }
    return { norm: norm, from: from, to: to };
  }

  /* Returns, for every token, the [start, end) it covers in the original text,
     or null for special tokens and anything that could not be placed. */
  function align(text, tokens) {
    var v = normalizedView(text), norm = v.norm;
    var pos = 0, out = [];

    function span(a, b) {
      return b > a ? { start: v.from[a], end: v.to[b - 1] } : null;
    }

    for (var t = 0; t < tokens.length; t++) {
      var tok = tokens[t];
      if (tok === "[CLS]" || tok === "[SEP]" || tok === "[PAD]") { out.push(null); continue; }

      var cont = tok.indexOf("##") === 0 && tok.length > 2;
      var piece = cont ? tok.slice(2) : tok;
      if (!cont) while (pos < norm.length && SPACE.test(norm[pos])) pos++;

      if (tok === "[UNK]") {
        /* An unknown token stands for one whole word the vocabulary could not
           spell, or for a single punctuation mark. */
        var s = pos;
        if (pos < norm.length && PUNCT.test(norm[pos])) pos++;
        else while (pos < norm.length && !SPACE.test(norm[pos]) && !PUNCT.test(norm[pos])) pos++;
        out.push(span(s, pos));
        continue;
      }

      if (norm.substr(pos, piece.length) === piece) {
        out.push(span(pos, pos + piece.length));
        pos += piece.length;
        continue;
      }
      /* Characters the tokenizer drops (control characters, replacement
         characters) leave small gaps; look a little ahead rather than give up. */
      var found = norm.indexOf(piece, pos);
      if (found !== -1 && found - pos <= 24) {
        out.push(span(found, found + piece.length));
        pos = found + piece.length;
      } else {
        out.push(null);
      }
    }
    return out;
  }

  function typeOf(label) {
    if (!label || label === "O") return "O";
    var m = /^[BIES]-(.+)$/.exec(label);
    return m ? m[1] : label;
  }

  /**
   * rows: one entry per token, in order: { tok, label, score }
   *   tok   -- the token as the tokenizer spells it ("vila", "##s", "[CLS]")
   *   label -- the model's best label, "B-PERSON", "I-PERSON" or "O"
   *   score -- that label's probability
   *
   * Returns entity spans: { start, end, text, label, score }.
   */
  function spans(text, rows) {
    var offs = align(text, rows.map(function (r) { return r.tok; }));

    /* Whole words first: a word's pieces share one reading. */
    var words = [];
    for (var i = 0; i < rows.length; i++) {
      var o = offs[i];
      if (!o) continue;
      var r = rows[i];
      var cont = r.tok.indexOf("##") === 0 && r.tok.length > 2;
      var w = cont && words.length ? words[words.length - 1] : null;
      if (!w) {
        w = { start: o.start, end: o.end, parts: [], first: r };
        words.push(w);
      }
      w.end = Math.max(w.end, o.end);
      w.parts.push(r);
    }

    words.forEach(function (w) {
      var best = null;
      w.parts.forEach(function (p) {
        var ty = typeOf(p.label);
        if (ty !== "O" && (!best || p.score > best.score)) best = { type: ty, score: p.score };
      });
      if (!best) { w.type = "O"; return; }
      var agree = w.parts.filter(function (p) { return typeOf(p.label) === best.type; });
      w.type = best.type;
      /* A word where only one piece in four thinks it is a name is not
         confidently a name. */
      w.score = agree.reduce(function (a, p) { return a + p.score; }, 0) / w.parts.length;
      w.inside = /^I-/.test(w.first.label) && typeOf(w.first.label) === best.type;
    });

    var out = [], cur = null;
    words.forEach(function (w) {
      if (w.type === "O") { cur = null; return; }
      var gap = cur ? text.slice(cur.end, w.start) : "";
      var joins = cur && cur.label === w.type &&
                  (w.inside || /^[\s\-'.]*$/.test(gap)) && gap.length <= 3 && !/\n/.test(gap);
      if (joins) {
        cur.end = w.end;
        cur.scores.push(w.score);
      } else {
        cur = { start: w.start, end: w.end, label: w.type, scores: [w.score] };
        out.push(cur);
      }
    });

    return out.map(function (s) {
      var score = s.scores.reduce(function (a, b) { return a + b; }, 0) / s.scores.length;
      /* "Tata Consultancy Services." -- the sentence's full stop is not part
         of the name. */
      var a = s.start, b = s.end;
      while (b > a && /[\s.,;:!?)\]}"'\u201d\u2019]/.test(text[b - 1])) b--;
      while (a < b && /[\s(\[{"'\u201c\u2018]/.test(text[a])) a++;
      return { start: a, end: b, text: text.slice(a, b),
               label: s.label, score: Math.round(score * 1000) / 1000 };
    }).filter(function (s) { return s.end > s.start; });
  }

  /* Splits long text into pieces the model can take in one pass, preferring
     line and sentence boundaries so a name is never cut in half. */
  function chunks(text, max) {
    max = max || 900;
    var out = [], start = 0;
    while (start < text.length) {
      var end = Math.min(text.length, start + max);
      if (end < text.length) {
        var window = text.slice(start, end);
        var cut = Math.max(window.lastIndexOf("\n"), window.lastIndexOf(". "),
                           window.lastIndexOf("; "));
        if (cut < max * 0.5) cut = window.lastIndexOf(" ");
        if (cut > max * 0.3) end = start + cut + 1;
      }
      out.push({ start: start, text: text.slice(start, end) });
      start = end;
    }
    return out;
  }

  return { align: align, spans: spans, chunks: chunks, normalizedView: normalizedView };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueNer;
