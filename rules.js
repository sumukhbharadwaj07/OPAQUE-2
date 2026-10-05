/* Opaque -- user-defined redaction rules.
 *
 * People want control beyond the built-in detectors: hide a salary column, drop
 * rows 2 to 5, blank out every mention of a client's name, never let the model
 * see anything about their health. They should be able to say so in ordinary
 * words, the way they would say it to a person.
 *
 * This parser is deliberately local and deterministic rather than a model.
 * Sending the instruction to a model would be slower, would need a network, and
 * -- worse -- the instruction itself often names the sensitive thing ("hide the
 * Acme contract column"), so shipping it off to be interpreted would leak the
 * very detail the user is trying to protect.
 *
 * What it understands:
 *   hide / block / redact / mask / blur / anonymise / scrub / keep private ...
 *   don't send / never share / don't mention / don't let the model see X  = hide X
 *   X is private / X is confidential / X should be hidden                = hide X
 *   don't hide / stop hiding / show / unhide / allow / X is fine          = undo or allow
 *   several things at once: "hide names, emails and phone numbers",
 *                           "hide the salary and phone columns"
 *   columns, rows, words, categories, and things in pictures
 */
var OpaqueRules = (function () {
  "use strict";

  /* ---------------------------------------------------------------- intent */

  var HIDE_VERBS = "hide|block|redact|mask|remove|censor|drop|exclude|omit|blur|cover|obscure|" +
    "black\\s*out|blank\\s*out|anonymi[sz]e|pseudonymi[sz]e|scrub|strip(?:\\s+out)?|sanitise|sanitize|" +
    "conceal|suppress|leave\\s+out|take\\s+out|cut\\s+out|get\\s+rid\\s+of|erase|protect|filter(?:\\s+out)?|" +
    "keep\\s+out|x\\s+out";
  var HIDE = new RegExp("\\b(" + HIDE_VERBS + ")\\b", "i");
  /* "don't SEND x" hides x; "don't HIDE x" allows it. */
  var NEG_SHARE = /\b(?:don'?t|do\s+not|never|please\s+don'?t|shouldn'?t|should\s+not|must\s+not|mustn'?t)\s+(?:ever\s+)?(send|share|show|mention|include|reveal|expose|leak|pass(?:\s+on)?|give\s+away|tell|disclose|upload|let\s+(?:the\s+)?(?:model|ai|gemini|server|llm|it|them|anyone)\s+(?:see|know|read))\b/i;
  /* "I don't want Gemini to see my salary" */
  var NO_WANT = /\b(?:i\s+)?(?:don'?t|do\s+not|never)\s+want\s+(?:the\s+|my\s+)?(?:model|ai|gemini|server|llm|it|anyone|them|others|chatbot|bot)\s+to\s+(?:see|know|read|have|get|receive)\b|\b(?:don'?t|do\s+not)\s+want\b.+\bto\s+be\s+(?:seen|sent|shared|visible|read)\b/i;
  var NEG_HIDE = new RegExp("\\b(?:don'?t|do\\s+not|never|stop|no\\s+need\\s+to|no\\s+longer|please\\s+don'?t)\\s+(?:" + HIDE_VERBS + "|hiding|masking|blocking|redacting)\\b", "i");
  var SHOW = /\b(show|unhide|un-?hide|unmask|un-?mask|allow|reveal|stop\s+hiding|un-?block|let\s+through|whitelist|permit)\b/i;
  var PRIVATE_STATE = /\b(?:is|are)\s+(?:private|sensitive|confidential|secret|personal|classified)\b|\bshould\s+(?:be\s+|stay\s+|remain\s+)?(?:hidden|private|masked|secret|confidential|redacted)\b|\bkeep\b.+\b(?:private|secret|hidden|confidential|to\s+(?:myself|yourself))\b/i;
  var FINE_STATE = /\b(?:is|are)\s+(?:fine|ok|okay|public|not\s+(?:private|sensitive|secret|confidential)|safe\s+to\s+(?:send|share|show))\b|\bit'?s\s+(?:fine|ok|okay)\s+to\s+(?:send|share|show)\b|\byou\s+can\s+(?:send|share|show)\b/i;

  /* Words that carry intent but name nothing. */
  var FILLER = /\b(?:please|kindly|can\s+you|could\s+you|would\s+you|will\s+you|i\s+want\s+(?:you\s+)?to|i'?d\s+like\s+(?:you\s+)?to|make\s+sure\s+(?:to|you|that)?|always|from\s+now\s+on|going\s+forward|in\s+future|in\s+the\s+future|every\s+time|everywhere|any|anything|all|every|each|my|our|the|a|an|of|in|on|from|for|with|when|while|sending|any\s+more|anymore|also|too|as\s+well|ever|to\s+(?:the\s+)?(?:model|ai|gemini|server|llm|chatbot|bot)|messages?|chats?|files?|documents?|screens?|images?|pictures?|photos?\s+of|it|them|these|those|this|that)\b/gi;

  /* --------------------------------------------------------------- entities
   * Order matters: "email addresses" must read as email, not as postal
   * address, so the more specific patterns come first. */
  var ENTITY_WORDS = [
    [/\be-?mail\s*(?:address(?:es)?|ids?)\b|\bmail\s*ids?\b|\be-?mails?\b/i, "EMAIL", "email addresses"],
    [/\bip\s*address(?:es)?\b|\bmac\s*address(?:es)?\b|\bdevice\s*ids?\b|\bips\b/i, "IP", "IP and device addresses"],
    [/\bdates?\s+of\s+births?\b|\bbirth\s*dates?\b|\bbirthdays?\b|\bdobs?\b/i, "DOB", "dates of birth"],
    [/\bpostal\s+address(?:es)?\b|\bhome\s+address(?:es)?\b|\bstreet\s+address(?:es)?\b|\bwhere\s+i\s+(?:live|stay)\b|(?<!e-?mail\s|ip\s|mac\s)\baddress(?:es)?\b|\bresidence\b/i,
      "ADDR", "postal addresses"],
    [/\busernames?\b|\buser\s*names?\b|\buser\s*ids?\b|\blogin\s*(?:ids?|names?)\b|\bhandles?\b/i, "USERNAME", "usernames"],
    [/\bpasswords?\b|\bpass\s*codes?\b|\bpins?\b|\botps?\b|\bsecrets?\b|\bcredentials?\b|\bapi\s*keys?\b|\btokens?\b|\bcvvs?\b/i, "SECRET", "passwords, PINs and other secrets"],
    [/\baccount\s*(?:numbers?|nos?|details?)\b|\bbank\s*(?:details?|accounts?|info)\b|\bifsc\b|\bupi\s*ids?\b|\bupi\b|\bcard\s*(?:numbers?|details?)\b|\bcredit\s*cards?\b|\bdebit\s*cards?\b/i, "ACCOUNT", "bank and card details"],
    [/\bidentity\s*(?:numbers?|documents?)\b|\bvoter\s*ids?\b|\bgovernment\s*ids?\b|\bgovt\s*ids?\b|\bid\s*(?:numbers?|nos?)\b|\bids\b|\baadhaa?r\b|\bpans?\b|\bpassports?\b|\blicen[cs]es?\b|\bssns?\b/i, "ID", "ID numbers"],
    [/\b(?:phone|mobile|contact|whatsapp|cell)\s*(?:numbers?|nos?)\b|\bphones?\b|\bmobiles?\b/i, "PHONE", "phone numbers"],
    [/\bnames?\b|\bpeople\b|\bpersons?\b|\bpeoples?'?\s+names?\b|\bwho\s+(?:someone|people)\s+(?:is|are)\b|\bsurnames?\b/i, "NAME", "names"],
    [/\bcompan(?:y|ies)\b|\borgani[sz]ations?\b|\bemployers?\b|\bbusiness(?:es)?\b|\bfirms?\b|\bclients?\b|\bbanks?\b|\bschools?\b|\bcolleges?\b|\buniversit(?:y|ies)\b|\bbrands?\b|\bwhere\s+i\s+work\b/i, "ORG", "organisations"],
    [/\bplaces?\b|\blocations?\b|\bcit(?:y|ies)\b|\btowns?\b|\bvillages?\b|\bstates?\b|\bareas?\b|\blocalit(?:y|ies)\b|\bneighbou?rhoods?\b|\bwhere\s+i\s+(?:am|come)\s+from\b/i, "PLACE", "places"],
    [/\bhealth\b|\bmedical\b|\bdiagnos(?:is|es)\b|\bdiseases?\b|\bconditions?\b|\bmedications?\b|\bmedicines?\b|\bprescriptions?\b|\billness(?:es)?\b|\bsymptoms?\b|\bmental\s+health\b/i, "HEALTH", "health information"],
    [/\breligions?\b|\bcastes?\b|\bbeliefs?\b|\bcommunit(?:y|ies)\b|\bfaith\b/i, "BELIEF", "religion and caste"],
    [/\bsexuality\b|\bsexual\s+orientation\b|\bgender\s+identity\b/i, "SEXUALITY", "sexual orientation"],
    [/\blegal\b|\bcriminal\s+records?\b|\bcourt\s+cases?\b|\barrests?\b|\bpolice\s+cases?\b/i, "LEGAL", "legal matters"],
    [/\bsalar(?:y|ies)\b|\bpay\b|\bcompensation\b|\bctc\b|\bincome\b|\bwages?\b|\bearnings?\b|\bstipends?\b/i, "SALARY", "salary values"],
    [/\bamounts?\b|\bmoney\b|\bprices?\b|\bcosts?\b|\bfigures?\b|\bbalances?\b|\btransactions?\b|\bpayments?\b|\bfinanc(?:es|ial\s+(?:info|details|figures))\b/i, "MONEY", "money amounts"],
    [/\bages?\b|\bhow\s+old\b/i, "AGE", "ages"],
    [/\bdates?\b/i, "DATE", "dates"],
    [/\blinks?\b|\burls?\b|\bwebsites?\b/i, "URL", "links"],
    [/\bnumbers?\b|\bdigits?\b|\bfigures\b/i, "NUMBER", "all numbers"]
  ];

  /* What each category is called in a spreadsheet header. */
  var COLUMN_SYNONYMS = {
    money: ["amount", "amt", "price", "cost", "salary", "pay", "ctc", "income", "balance", "total",
            "value", "revenue", "fee", "fees", "charges", "rs", "inr", "rupees", "\u20b9", "payment",
            "debit", "credit", "paid", "due"],
    salary: ["salary", "pay", "ctc", "compensation", "income", "wage", "wages", "stipend", "gross", "net pay"],
    phone: ["phone", "mobile", "contact", "cell", "tel", "telephone", "whatsapp", "phone no", "mobile no"],
    contact: ["phone", "mobile", "contact", "email", "e-mail", "cell", "whatsapp"],
    email: ["email", "e-mail", "mail", "email id", "mail id"],
    name: ["name", "full name", "first name", "last name", "surname", "employee", "customer",
           "person", "candidate", "student", "patient", "member"],
    address: ["address", "addr", "location", "city", "street", "residence", "pincode", "pin code", "zip"],
    dob: ["dob", "date of birth", "birth", "birthday", "birth date"],
    id: ["id", "aadhaar", "aadhar", "pan", "ssn", "passport", "employee id", "emp id", "customer id", "uid"],
    account: ["account", "acct", "a/c", "ifsc", "iban", "upi", "card", "bank"],
    age: ["age"],
    gender: ["gender", "sex"]
  };

  function ordinalToIndex(word) {
    var map = { first: 1, second: 2, third: 3, fourth: 4, fifth: 5, sixth: 6,
                seventh: 7, eighth: 8, ninth: 9, tenth: 10, last: -1 };
    return map[String(word).toLowerCase()] || null;
  }

  function quoted(text) {
    var m = text.match(/["'\u201c\u2018]([^"'\u201d\u2019]+)["'\u201d\u2019]/);
    return m ? m[1].trim() : null;
  }

  /* ----------------------------------------------------------------- parse */

  function fail(why) { return { ok: false, why: why }; }

  var HELP = "Try naming a column, a row range, a word in quotes, or a category. For example: " +
    "\u201chide the salary column\u201d, \u201cblock rows 2 to 5\u201d, \u201credact anything " +
    "containing Acme\u201d, \u201chide names and addresses\u201d, or \u201cnever send anything " +
    "about my health\u201d.";

  /**
   * Turns one instruction into rules, or a plain refusal the caller can show.
   * Returns { ok, action: "add"|"remove"|"allow"|"list"|"clear", rule, rules }.
   * `rule` is the first of `rules`, kept for callers that expect one.
   */
  function parse(input) {
    var text = String(input || "").trim().replace(/[.!]+$/, "");
    if (!text) return fail("Say what you would like hidden.");

    if (/^\s*(list|show|what\s+are)\s+(the\s+|my\s+)?rules?\s*\??$/i.test(text)) return { ok: true, action: "list" };
    if (/^\s*(clear|delete|remove|reset)\s+(all\s+|the\s+|my\s+)?rules?\s*$/i.test(text)) return { ok: true, action: "clear" };

    /* intent */
    var intent = null;
    if (NEG_HIDE.test(text)) intent = "allow";
    else if (NEG_SHARE.test(text) || NO_WANT.test(text)) intent = "hide";
    else if (HIDE.test(text)) intent = "hide";
    else if (FINE_STATE.test(text)) intent = "allow";
    else if (PRIVATE_STATE.test(text)) intent = "hide";
    else if (SHOW.test(text)) intent = "allow";
    if (!intent) {
      return fail("Start with hide, block, redact or mask \u2014 or say \u201cnever send X\u201d. " + HELP);
    }

    var rules = parseObject(text);
    if (!rules.length) return fail("I could not tell what to " + (intent === "hide" ? "hide" : "allow") + ". " + HELP);

    if (intent === "allow") {
      /* "don't hide the salary column" undoes that rule; "Mumbai is fine" is a
         new promise never to flag the word. */
      var action = rules.every(function (r) { return r.kind === "term"; }) &&
                   !/\b(stop\s+hiding|unhide|un-?hide|unmask|un-?block|show|reveal|don'?t\s+hide)\b/i.test(text)
        ? "allow" : "remove";
      if (action === "allow") {
        rules = rules.map(function (r) {
          return { kind: "allow", value: r.value, label: '"' + r.value + '"' };
        });
      } else {
        /* "stop hiding Acme" might mean the term rule or a promise: remove the
           rule, and the caller also offers to allow it. */
        rules = rules.map(function (r) { return r; });
      }
      return { ok: true, action: action, rule: rules[0], rules: rules };
    }
    return { ok: true, action: "add", rule: rules[0], rules: rules };
  }

  /* Reads what the instruction is about. Returns a list of rules. */
  function parseObject(text) {
    /* rows */
    var rowRange = text.match(/\brows?\s+(\d+)\s*(?:to|through|thru|-|\u2013|until|till)\s*(\d+)/i);
    if (rowRange) {
      return [{ kind: "row", from: +rowRange[1], to: +rowRange[2], label: "rows " + rowRange[1] + " to " + rowRange[2] }];
    }
    var rowList = text.match(/\brows?\s+((?:\d+\s*(?:,|and|&)\s*)+\d+)/i);
    if (rowList) {
      var nums = rowList[1].split(/\s*(?:,|and|&)\s*/).map(Number);
      return [{ kind: "rowset", rows: nums, label: "rows " + nums.join(", ") }];
    }
    var oneRow = text.match(/\brow\s+(?:number\s+)?(\d+)\b/i);
    if (oneRow) return [{ kind: "row", from: +oneRow[1], to: +oneRow[1], label: "row " + oneRow[1] }];
    var firstRows = text.match(/\b(first|last|top|bottom)\s+(\d+)\s+rows?\b/i);
    if (firstRows) {
      var n = +firstRows[2], isLast = /last|bottom/i.test(firstRows[1]);
      return [{ kind: isLast ? "lastrows" : "firstrows", count: n,
                label: (isLast ? "last " : "first ") + n + " rows" }];
    }

    /* columns by position */
    var colNum = text.match(/\bcolumns?\s+(?:number\s+)?(\d+)\b/i);
    if (colNum) return [{ kind: "colindex", index: +colNum[1], label: "column " + colNum[1] }];
    var colLetter = text.match(/\bcolumns?\s+([A-Za-z])\b(?!\s*\w*\s*(?:named|called))/);
    if (colLetter && !/\bcolumns?\s+(named|called|with|containing|titled)\b/i.test(text)) {
      var letter = colLetter[1].toUpperCase();
      return [{ kind: "colindex", index: letter.charCodeAt(0) - 64, label: "column " + letter }];
    }
    var colOrd = text.match(/\b(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|last)\s+column\b/i);
    if (colOrd) {
      return [{ kind: "colindex", index: ordinalToIndex(colOrd[1]), label: colOrd[1].toLowerCase() + " column" }];
    }

    /* columns by name, one or several: "the salary and phone columns" */
    var colNamed = text.match(/\bcolumns?\s+(?:named|called|titled|with\s+(?:the\s+)?header)\s+["']?([\w .\-\/]+?)["']?\s*$/i);
    var colBefore = text.match(/\b(?:the\s+)?["']?([\w .,&\-\/]+?)["']?\s+columns?\b/i);
    if (colNamed || colBefore) {
      var raw = (colNamed ? colNamed[1] : colBefore[1]).replace(new RegExp("\\b(" + HIDE_VERBS + ")\\b", "gi"), " ");
      raw = raw.replace(/\b(?:don'?t|do\s+not|never|stop|hiding|masking|blocking|redacting|showing|send|share|show|unhide|unmask|allow|reveal|keep|please|the|all|any|every|my|our)\b/gi, " ");
      var names = raw.split(/\s*(?:,|\band\b|&|\bor\b|\bplus\b)\s*/i).map(function (x) { return x.trim(); })
        .filter(function (x) { return x && !/^(first|last|next|that|this)$/i.test(x); });
      if (names.length) {
        return names.map(function (nm) {
          return { kind: "colname", name: nm, label: '"' + nm + '" column' };
        });
      }
    }

    /* things in pictures, located by Florence-2 */
    var VISUAL = [
      [/\bphotos?\b|\bphotographs?\b|\bpictures?\b|\bheadshots?\b|\bportraits?\b|\bselfies?\b/i, "photograph"],
      [/\bfaces?\b/i, "human face"],
      [/\bqr\s*codes?\b/i, "QR code"],
      [/\bbar\s*codes?\b/i, "barcode"],
      [/\bsignatures?\b/i, "signature"],
      [/\bstamps?\b|\bseals?\b/i, "official stamp"],
      [/\blogos?\b|\bemblems?\b/i, "logo"],
      [/\bfinger\s*prints?\b/i, "fingerprint"],
      [/\blicen[cs]e\s+plates?\b|\bnumber\s+plates?\b/i, "license plate"]
    ];
    for (var vi = 0; vi < VISUAL.length; vi++) {
      var vm = text.match(VISUAL[vi][0]);
      /* "photos of my kids" is about the photos; "photo ID number" is not */
      if (vm && !/\b(?:photo|picture)\s+id\b/i.test(text)) {
        /* Keep what the user said about which one: "the aadhaar logo" is not
           any logo, and the qualifier is often the only way to find it. */
        var before = text.slice(0, vm.index).trim().split(/\s+/);
        var qual = [];
        while (before.length && qual.length < 2) {
          var w = before.pop();
          if (!/^[\w'-]+$/.test(w) || HIDE.test(w) || SHOW.test(w) ||
              /^(the|a|an|all|any|every|this|that|those|these|my|out|in|on|of|send|share|show|never|don't|dont|not)$/i.test(w)) break;
          qual.unshift(w.toLowerCase());
        }
        var q = qual.join(" ");
        return [{ kind: "visual", phrase: VISUAL[vi][1], qualifier: q,
                  label: q ? q + " " + VISUAL[vi][1] : VISUAL[vi][1] }];
      }
    }

    /* a literal word or phrase */
    var qv = quoted(text);
    var containing = text.match(/\b(?:contain(?:ing|s)?|mention(?:ing|s)?|include(?:s|ing)?|matching|with\s+the\s+(?:word|name|term))\s+["']?([^"']+?)["']?\s*$/i);
    var wordOf = text.match(/\b(?:the\s+)?(?:word|term|text|string|value|phrase|codename|code\s*name|project(?:\s+name)?)\s+["']?([^"']+?)["']?\s*$/i);
    var term = qv || (containing && containing[1]) || (wordOf && wordOf[1]);
    if (term) {
      term = term.trim().replace(/[.?!]+$/, "");
      if (term.length >= 2) return [{ kind: "term", value: term, label: '"' + term + '"' }];
    }

    /* categories, possibly several: "names, emails and phone numbers" */
    var found = [];
    var rest = text;
    /* "contact details" is two categories at once */
    if (/\bcontact\s*(?:details?|info(?:rmation)?|numbers?\s+and\s+emails?)\b/i.test(rest)) {
      found.push({ kind: "entity", entity: "PHONE", label: "phone numbers" });
      found.push({ kind: "entity", entity: "EMAIL", label: "email addresses" });
      rest = rest.replace(/\bcontact\s*(?:details?|info(?:rmation)?)\b/i, " ");
    }
    ENTITY_WORDS.forEach(function (e) {
      var m = rest.match(e[0]);
      if (m) {
        if (!found.some(function (f) { return f.entity === e[1]; })) {
          found.push({ kind: "entity", entity: e[1], label: e[2] });
        }
        /* "email addresses" must not also count as "addresses" */
        rest = rest.replace(e[0], " ");
      }
    });
    /* A bare "numbers" next to a real category ("phone numbers") is not a
       request to hide every number. */
    if (found.length > 1) found = found.filter(function (f) { return f.entity !== "NUMBER" && f.entity !== "DATE"; });
    if (found.length) return found;

    /* Anything left is a name or a word the user wants kept out:
       "hide Acme", "never mention Project Falcon", "Priya is private". */
    var obj = text
      .replace(NEG_SHARE, " ").replace(NEG_HIDE, " ").replace(NO_WANT, " ")
      .replace(new RegExp("\\b(" + HIDE_VERBS + ")\\b", "gi"), " ")
      .replace(/\b(?:show|unhide|allow|reveal|stop\s+hiding|is|are|should\s+be|stay|remain|keep|fine|ok|okay|public|private|sensitive|confidential|secret|personal|not|safe\s+to\s+(?:send|share|show)|it'?s|you\s+can|send|share|mention)\b/gi, " ")
      .replace(FILLER, " ")
      .replace(/[,;:?]+/g, " ")
      .replace(/\s+/g, " ").trim();
    if (obj && obj.length >= 2 && obj.split(" ").length <= 5 && !/^(it|this|that|them|stuff|things?)$/i.test(obj)) {
      return obj.split(/\s*(?:,|\band\b|&)\s*/).filter(Boolean).map(function (x) {
        return { kind: "term", value: x, label: '"' + x + '"' };
      });
    }
    return [];
  }

  /* ------------------------------------------------------------------ apply */

  var NEEDS_MODEL = { NAME: true, ADDR: true, ORG: true, PLACE: true };

  var ENTITY_RE = {
    EMAIL:  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    PHONE:  /(?:\+?91[ -]?)?\b[6-9]\d{4}[ -]?\d{5}\b/g,
    DOB:    /\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2}\b/g,
    DATE:   /\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)?\d{2}\b/g,
    MONEY:  /(?:\u20b9|Rs\.?|INR|\$)\s?[\d,]+(?:\.\d{1,2})?|\b\d{1,3}(?:,\d{2,3})+(?:\.\d{1,2})?\b/g,
    SALARY: /(?:\u20b9|Rs\.?|INR|\$)\s?[\d,]+(?:\.\d{1,2})?|\b\d{4,}\b/g,
    NUMBER: /\b\d[\d,.]*\b/g,
    URL:    /\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/g
  };

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  /** Applies term and pattern-based entity rules to a plain string. The leak
      guard applies the rest (names, places, health ...) with the model. */
  function applyToText(text, rules) {
    var out = String(text == null ? "" : text);
    var count = 0;
    (rules || []).forEach(function (r) {
      if (r.kind === "term") {
        var re = new RegExp(escapeRe(r.value), "gi");
        out = out.replace(re, function () { count++; return "[HIDDEN]"; });
      } else if (r.kind === "entity" && ENTITY_RE[r.entity]) {
        ENTITY_RE[r.entity].lastIndex = 0;
        out = out.replace(ENTITY_RE[r.entity], function () {
          count++; return "[" + r.entity + "]";
        });
      }
    });
    return { text: out, count: count };
  }

  function normHeader(h) {
    return String(h == null ? "" : h).trim().toLowerCase().replace(/[_\-.]+/g, " ").replace(/\s+/g, " ");
  }

  function near(a, b) {
    if (a === b) return true;
    if (Math.abs(a.length - b.length) > 1 || a.length < 5) return false;
    /* one typo: "salry" for "salary" */
    var i = 0, j = 0, diff = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++diff > 1) return false;
      if (a.length > b.length) i++;
      else if (b.length > a.length) j++;
      else { i++; j++; }
    }
    return diff + (a.length - i) + (b.length - j) <= 1;
  }

  /* Does a header answer to what the user called the column? */
  function headerMatches(header, want) {
    if (!header) return false;
    var w = normHeader(want).replace(/s$/, "");
    if (!w) return false;
    var words = header.split(" ");
    if (header === w || header.replace(/s$/, "") === w) return true;
    if (words.some(function (x) { return near(x.replace(/s$/, ""), w); })) return true;
    if ((" " + header + " ").indexOf(" " + w + " ") !== -1) return true;
    if (header.indexOf(w) !== -1 && w.length >= 4) return true;
    var syn = COLUMN_SYNONYMS[w] || COLUMN_SYNONYMS[w + "s"];
    if (syn) {
      return syn.some(function (s) {
        return header === s || (" " + header + " ").indexOf(" " + s + " ") !== -1 ||
               (s.length >= 4 && header.indexOf(s) !== -1);
      });
    }
    return false;
  }

  /**
   * Applies every rule to a grid. Row and column numbers are 1-based and count
   * the header, because that is how people read a spreadsheet.
   */
  function applyToGrid(rows, rules) {
    var header = rows.length ? rows[0].map(normHeader) : [];
    var hideCols = {}, hideRows = {};
    var count = 0;

    (rules || []).forEach(function (r) {
      if (r.kind === "colindex") {
        var idx = r.index === -1 ? header.length : r.index;
        hideCols[idx - 1] = true;
      } else if (r.kind === "colname") {
        header.forEach(function (h, i) { if (headerMatches(h, r.name)) hideCols[i] = true; });
      } else if (r.kind === "row") {
        for (var n = r.from; n <= r.to; n++) hideRows[n - 1] = true;
      } else if (r.kind === "rowset") {
        r.rows.forEach(function (n) { hideRows[n - 1] = true; });
      } else if (r.kind === "firstrows") {
        for (var a = 1; a <= r.count; a++) hideRows[a] = true;   // skip header
      } else if (r.kind === "lastrows") {
        for (var b = 0; b < r.count; b++) hideRows[rows.length - 1 - b] = true;
      }
    });

    var cellRules = (rules || []).filter(function (r) { return r.kind === "term" || r.kind === "entity"; });
    var out = rows.map(function (row, ri) {
      return row.map(function (cell, ci) {
        if (hideRows[ri] && ri !== 0) { count++; return "[HIDDEN ROW]"; }
        if (hideCols[ci] && ri !== 0) { count++; return "[HIDDEN]"; }
        var t = applyToText(cell, cellRules);
        count += t.count;
        return t.text;
      });
    });

    return { rows: out, count: count,
             hiddenColumns: Object.keys(hideCols).length,
             hiddenRows: Object.keys(hideRows).length };
  }

  function describe(rule) {
    switch (rule.kind) {
      case "colname":   return "Hide the " + rule.label;
      case "colindex":  return "Hide " + rule.label;
      case "row":       return "Hide " + rule.label;
      case "rowset":    return "Hide " + rule.label;
      case "firstrows": return "Hide the " + rule.label;
      case "lastrows":  return "Hide the " + rule.label;
      case "term":      return "Hide every occurrence of " + rule.label;
      case "entity":    return "Hide all " + rule.label;
      case "visual":    return "Hide the " + rule.label + " in images";
      case "allow":     return "Never hide " + rule.label;
      default:          return "Hide " + (rule.label || rule.kind);
    }
  }

  function sameRule(a, b) {
    if (!a || !b) return false;
    if (a.kind === "term" && b.kind === "term") return String(a.value).toLowerCase() === String(b.value).toLowerCase();
    if (a.kind === "allow" && b.kind === "allow") return String(a.value).toLowerCase() === String(b.value).toLowerCase();
    if (a.kind === "entity" && b.kind === "entity") return a.entity === b.entity;
    if (a.kind === "colname" && b.kind === "colname") return normHeader(a.name) === normHeader(b.name);
    return a.kind === b.kind && (a.label || "") === (b.label || "");
  }

  /* Whether a rule is carried out by the personal-data model, which the side
     panel loads on start. */
  function needsModel(rule) {
    return !!(rule && rule.kind === "entity" && NEEDS_MODEL[rule.entity]);
  }

  return { parse: parse, applyToText: applyToText, applyToGrid: applyToGrid,
           describe: describe, sameRule: sameRule, needsModel: needsModel,
           headerMatches: headerMatches, ENTITY_RE: ENTITY_RE };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueRules;
