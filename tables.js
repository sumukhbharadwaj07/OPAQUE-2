/* Opaque -- table reconstruction from OCR.
 *
 * Florence-2 returns text with a box around each piece. That is a bag of
 * fragments, not a table, so a rule like "hide the money column" has nothing to
 * act on. But the structure is still there in the geometry: cells in the same
 * row share a vertical band, cells in the same column share a horizontal one.
 *
 * Recovering the grid is therefore a clustering problem rather than a vision
 * problem, which is fortunate -- it is exact, fast, and does not depend on a
 * model understanding what a table is.
 */
var OpaqueTable = (function () {
  "use strict";

  function cy(b) { return (b[1] + b[3]) / 2; }
  function cx(b) { return (b[0] + b[2]) / 2; }
  function height(b) { return b[3] - b[1]; }

  function median(xs) {
    if (!xs.length) return 0;
    var s = xs.slice().sort(function (a, b) { return a - b; });
    var m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  /* Groups values that sit close together on one axis. Returns cluster centres. */
  function cluster1d(values, gap) {
    if (!values.length) return [];
    var s = values.slice().sort(function (a, b) { return a - b; });
    var groups = [[s[0]]];
    for (var i = 1; i < s.length; i++) {
      if (s[i] - s[i - 1] <= gap) groups[groups.length - 1].push(s[i]);
      else groups.push([s[i]]);
    }
    return groups.map(function (g) {
      return g.reduce(function (a, b) { return a + b; }, 0) / g.length;
    });
  }

  /**
   * Turns OCR regions into a grid.
   *
   * regions: [{ text, box:[x0,y0,x1,y1] }]
   * returns: { rows, cells, confidence }
   *   rows  -- array of arrays of strings
   *   cells -- same shape, each entry { text, box } or null
   *   confidence -- 0..1, how table-like the layout actually is
   */
  function fromRegions(regions, opts) {
    opts = opts || {};
    var boxed = (regions || []).filter(function (r) {
      return r && r.box && r.text && String(r.text).trim();
    });
    if (boxed.length < 4) {
      return { rows: [], cells: [], confidence: 0, why: "too few text regions" };
    }

    var medH = median(boxed.map(function (r) { return height(r.box); })) || 10;
    var rowTol = medH * (opts.rowTolerance || 0.62);

    /* ---- rows: group by vertical centre ---- */
    var sorted = boxed.slice().sort(function (a, b) { return cy(a.box) - cy(b.box); });
    var rows = [];
    sorted.forEach(function (r) {
      var last = rows[rows.length - 1];
      if (last && Math.abs(cy(r.box) - last.center) <= rowTol) {
        last.items.push(r);
        last.center = last.items.reduce(function (s, x) { return s + cy(x.box); }, 0)
                      / last.items.length;
      } else {
        rows.push({ center: cy(r.box), items: [r] });
      }
    });
    rows.forEach(function (row) {
      row.items.sort(function (a, b) { return a.box[0] - b.box[0]; });
    });

    /* ---- columns: cluster left edges across every row ---- */
    var lefts = boxed.map(function (r) { return r.box[0]; });
    var colGap = opts.colGap || Math.max(medH * 1.4, 18);
    var centers = cluster1d(lefts, colGap);
    if (centers.length < 2) {
      return { rows: [], cells: [], confidence: 0, why: "no column structure" };
    }

    function columnOf(box) {
      var best = 0, bestD = Infinity;
      for (var i = 0; i < centers.length; i++) {
        var d = Math.abs(box[0] - centers[i]);
        if (d < bestD) { bestD = d; best = i; }
      }
      return best;
    }

    /* ---- place each fragment ---- */
    var grid = [], cells = [];
    rows.forEach(function (row) {
      var line = new Array(centers.length).fill("");
      var cline = new Array(centers.length).fill(null);
      row.items.forEach(function (item) {
        var c = columnOf(item.box);
        if (line[c]) {
          /* two fragments in one cell: join them and widen the box */
          line[c] += " " + item.text;
          var b = cline[c].box, n = item.box;
          cline[c] = { text: line[c], box: [Math.min(b[0], n[0]), Math.min(b[1], n[1]),
                                            Math.max(b[2], n[2]), Math.max(b[3], n[3])] };
        } else {
          line[c] = item.text;
          cline[c] = { text: item.text, box: item.box.slice() };
        }
      });
      grid.push(line);
      cells.push(cline);
    });

    /* ---- how confident are we that this really is a table? ---- */
    var filled = 0, total = 0;
    grid.forEach(function (line) {
      line.forEach(function (c) { total++; if (c) filled++; });
    });
    var density = total ? filled / total : 0;
    var multiCell = grid.filter(function (l) {
      return l.filter(Boolean).length >= 2;
    }).length;
    var regularity = grid.length ? multiCell / grid.length : 0;
    var confidence = Math.max(0, Math.min(1, density * 0.45 + regularity * 0.55));

    return { rows: grid, cells: cells, confidence: confidence,
             columns: centers.length, rowCount: grid.length };
  }

  /**
   * Applies grid rules and reports which boxes should be covered on screen.
   * Returns { rows, boxes, count } where boxes are the original OCR
   * coordinates of every cell the rules hid.
   */
  function applyRules(table, rules, rulesApi) {
    var applied = rulesApi.applyToGrid(table.rows, rules);
    var boxes = [];
    applied.rows.forEach(function (line, ri) {
      line.forEach(function (cell, ci) {
        var before = table.rows[ri] && table.rows[ri][ci];
        if (before && cell !== before) {
          var src = table.cells[ri] && table.cells[ri][ci];
          if (src && src.box) {
            boxes.push({ box: src.box, ph: /ROW/.test(cell) ? "[HIDDEN ROW]" : "[HIDDEN]",
                         severity: "high" });
          }
        }
      });
    });
    return { rows: applied.rows, boxes: boxes, count: applied.count };
  }

  function toText(rows) {
    return rows.map(function (r) { return r.join(" | "); }).join("\n");
  }

  return { fromRegions: fromRegions, applyRules: applyRules, toText: toText };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueTable;
