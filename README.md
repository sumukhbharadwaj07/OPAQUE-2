# Opaque

A browser extension for **SIH26171 — On-device visual perception for light-weight
browser agents** (ISRO).

The screen is read on your own machine. Anything sensitive is covered **before**
a screenshot is ever taken, and only placeholders are sent to the reasoning
model. You can then ask follow-up questions about the page, and the model keeps
the context without ever receiving the values.

**What runs on your machine:** two small models and a rule engine.

| Piece | Job | Size |
|---|---|---|
| bert-small-pii (text model) | names, places, organisations, other personal data in text | 29 MB |
| Florence-2 base (vision model) | reading text in pictures, finding photos and QR codes | ~215 MB |
| `lib/guard.js` (rules) | passwords, IDs, addresses, hints, memory, your own rules | - |

Both models download once from Hugging Face and are cached by the extension.
All code is vendored in `vendor/` (see its README for versions and hashes);
nothing executable is fetched at runtime.

---

## Install (2 minutes)

1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked**
4. Choose this `opaque` folder
5. Open any ordinary website and click the Opaque icon

It will not run on `chrome://` pages. That is a browser restriction, not a bug.

---

## Using it

Everything you give Opaque is cleaned on your own machine before any of it
reaches a model. That applies to all four kinds of input:

| Input | How the text is obtained | Cleaned by |
|---|---|---|
| Your typed message | already text | the gate |
| CSV, TSV, TXT, MD, JSON | read directly | the gate |
| PDF | pdf.js pulls the embedded text; if the PDF is scanned, pages are rendered and read by Florence-2 | the gate |
| XLSX, XLS, XLSM | SheetJS reads every cell | the gate |
| PNG, JPG, WEBP, GIF | Florence-2 reads the text out of the picture | the gate |
| The current screen | the page's own structure, via **Read this screen** | the gate |

Attach files with the paperclip, or drag them onto the panel. Each attachment
shows what was found in it before you send anything.

- **Chat** — ask anything. Follow-up questions keep the context.
- **Found** — every detected value, which tier caught it, and which input it
  came from.
- **Sent** — the exact text that leaves your machine.

The reasoning server defaults to **Mock**, which needs no internet and cannot
fail. Use it for a live demo, and switch to Gemini or Ollama for real answers.

---

## How chat is checked before it leaves

Every message, file, OCR result and screen description goes through one gate,
`lib/guard.js`, which layers several independent readings:

1. **Normalise** -- invisible characters, look-alike letters, values spelled
   out (`a d i 1 2 3`, `nine eight seven ...`, `double nine`), text written
   backwards.
2. **Detectors** -- checksums and formats (Aadhaar, cards, PAN, IFSC ...).
3. **Cues** -- a word that announces a value and the slot it points to, in
   either direction: `my password for gmail is X`, `X is my password`,
   `change it from X to Y`, `door code for my building is 7291`.
4. **Structure** -- `key: value`, `KEY=VALUE`, JSON, `user:pass@host`, `?token=`.
5. **People** -- names after "my name is", "my wife", "Dr."; employers;
   dates of birth; personal amounts; Indian addresses (H.No, Sector, Nagar,
   Dist, Tal, PIN code), including multi-line address blocks.
6. **Text model** -- its findings graded by context: "my son Arjun" is hidden,
   "tell me about Mahatma Gandhi" is not.
7. **Shape** -- secret-looking tokens, UPI IDs, long account numbers, base64 /
   hex / URL-encoded payloads that decode to something private.
8. **Memory** -- anything hidden earlier is hidden again, whole, reversed,
   spaced out or in parts. Kept in session storage only, never on disk.

Each finding is **high** (always hidden), **medium** (hidden, but shown to you
first so you can reveal it) or **low** (noted, not hidden). Things that cannot
be hidden without destroying the question -- a health condition, a hint like
"my password is my dog's name plus my birth year" -- raise a **warning**.

Before sending, a review card shows the message exactly as the model will see
it. Settings choose when it appears: when something is uncertain (default),
always, or never. Placeholders are numbered (`[PERSON_1]`, `[ADDRESS_2]`) and
stay the same across the conversation, so the model can still reason about who
is who.

Measured on the labelled set in `test/guard.js`: **108/108** leaked values
caught, **0/62** ordinary questions altered. That set is ours, not an
independent benchmark -- treat it as a regression floor, not a claim of
coverage.

---

## Secrets that have no pattern

An Aadhaar number has a checksum. A password has nothing -- `adi@123`,
`hunter2` and `adjhfb124` share no shape at all, so nothing about the value
itself proves it is a secret.

The first version looked for the word "password" next to it. That broke the
moment someone typed **"oassword"** -- an exact keyword match fails in exactly
the situation where a leak matters most.

So two independent signals are combined instead.

**The trigger word is matched approximately.** `oassword`, `pasword`, `passwrd`,
`p@ssw0rd` and `pass word` all resolve to `password`, through leetspeak folding,
bounded edit distance, and joining up to three adjacent tokens.

**The value is scored on its own properties** -- character classes, length,
Shannon entropy, and whether it looks like an ordinary English word. Neither
signal has to be perfect: a shaky trigger beside a strong-looking value still
crosses the line, and a confident trigger pulls through a modest-looking value.

Then, rather than hiding the value behind a bare tag, Opaque substitutes a
**description** of it:

```
you   : can i change my oassword to adjhfb124
sent  : can i change my oassword to [SECRET: 9 chars; lowercase+digits;
        letters then digits]
```

The model gives an accurate, specific verdict on that password and never
receives it. This is the clearest statement of the project's argument: remove
the value, keep everything needed to stay useful.

Also caught: `cvv 834`, `my security code is 834`, `one time password 482913`,
`pin to 4821`, and API keys by shape alone (`sk-`, `AIza`, `ghp_`, `xoxb-`,
`AKIA`, JWTs). Long high-entropy strings are flagged whatever the sentence says.

Deliberately **not** caught, because they are ordinary English: "The password
field is empty", "Forgot Password?", "what is a strong password?", "change my
password to something stronger", "password manager recommended", "see page 834
for details".

---

## Pages that are only a picture

A scanned form, an ID card, a screenshot someone opened in a tab -- these pages
contain no text at all. Every word is pixels inside an image.

Reading the page structure finds nothing there, which is worse than it sounds:
the user believes the screen was checked, and it was, but there was nothing in
the page to check. So when **Read this screen** finds little or no text, Opaque
reads the captured picture instead, with Florence-2, and paints boxes over
anything sensitive it finds there.

Numbers read out of a picture are not held to their checksums. OCR drops and
swaps digits -- on a real Aadhaar card Florence-2 read `7730 0889 2163` as
`7730 089 2163` -- and a checksum that fails for that reason would let the real
number through. So in text from an image, anything grouped like an Aadhaar,
VID or card number is covered as `[ID_NUMBER]` whether or not it verifies.

Photographs of people and QR codes are covered too, in every picture that gets
read, without needing a rule; on an ID card they identify the person as surely
as the number does. Florence-2 answers "QR code" and "photograph" with a box
around the whole image, which is its way of not knowing, so Opaque asks with the
wordings that measurably work ("barcode", "photo of a person") and discards any
box that covers nearly the whole picture. The text sent to the model says what
was covered, e.g. `COVERED IN THE PICTURE: [PHOTOGRAPH], [QR_CODE]`.

Turn either of these off under Settings if you would rather not.

---

## Tests

```bash
bash test/all.sh
```

About 560 checks, no browser needed: detection, rules, span mapping and table
reconstruction (`run.js`), the leak guard against a labelled set (`guard.js`),
and wiring plus security properties -- policies, message origins, vendored
file hashes, ASCII-only scripts (`wiring.js`).

Three things are **not** covered, because they need a real browser, and saying
otherwise would be worse than admitting it: the sandboxed worker loading a
library from a CDN, tab capture and cross-origin image fetching, and WebGPU.
Load the extension and watch the console for those.

---

## One model, kept small

Florence-2 is the only AI model in the extension. Reading text out of a
picture, reading scanned PDF pages, and finding "the photograph" or "the QR
code" all go to it. There is no separate OCR engine, face detector or QR
reader, so there is one download and one thing that can fail.

It is the smallest configuration that works: the **base** checkpoint (0.23B
parameters, not large), with 4-bit weights for the vision encoder, text
encoder and decoder. About 215 MB on the CPU (WebAssembly) and 255 MB on
WebGPU, fetched once and cached; WebGPU is used when available. The q4f16
variants are smaller still but were measured and rejected: they misread ID
numbers, and an OCR that turns `ABCDE1234F` into `ABCDE12345F` lets the PAN
slip past the checksum detectors.

Opaque also prefers the **original picture** over a screenshot of it. A page that
is one large image exposes its source, and the extension can fetch that
cross-origin where a page script could not, so small print is read at full
resolution rather than at whatever size the window happened to be.

---

## What Florence-2 actually does here

Florence-2 is a vision model. It takes text, but only as a *task*, not as an
instruction. Three of its tasks accept free wording, and Opaque uses two of
them:

| You type | Task used | What comes back |
|---|---|---|
| (nothing) | `<OCR_WITH_REGION>` | every piece of text, with a box |
| "hide the photograph" | `<CAPTION_TO_PHRASE_GROUNDING>` | boxes around the photograph |
| "blur the QR code" | `<OPEN_VOCABULARY_DETECTION>` | boxes around the QR code |

So `hide the photograph`, `blur the QR code`, `black out the signature`,
`obscure the face` and `redact the logo` all go to Florence-2 as text, and it
answers with coordinates. That is genuine text interaction with the model -- it
is being asked *where something is*, not what to do about it.

Logos are the weak spot. Florence-2 base cannot locate one on an ID card --
asked for "logo", "aadhaar logo" or "emblem", it answers with the whole image,
even on crops. So a rule that names *which* logo (`block the aadhaar logo`)
keeps that word, and any text region that reads as just that word -- the
printed wordmark -- is covered along with the emblem above it. It works where
the wordmark is in Latin script; Florence-2 reads Devanagari poorly, so a logo
labelled only "आधार" can still be missed.

What Florence-2 cannot do is follow an instruction like "hide the money column".
No vision model can; that is not one of its tasks.

---

## Tables inside pictures

A photograph of a spreadsheet has no columns as far as any OCR is concerned --
just fragments of text scattered across an image. But the structure is still
there in the geometry: cells in a row share a vertical band, cells in a column
share a horizontal one.

So Opaque rebuilds the grid by clustering the boxes Florence-2 returned. That
makes it a geometry problem rather than a vision problem, which is fortunate --
it is exact, instant, and does not depend on a model understanding what a table
is.

The upshot is that **"hide the money column" works on a photograph of a table
exactly as it works on a CSV**. The matching column is blacked out on screen and
replaced with `[HIDDEN]` in the text that gets sent. If the layout is too
irregular to read as a table, Opaque says so and applies the value rules only,
rather than guessing.

---

## Your own rules, in plain words

The **Rules** tab takes ordinary instructions:

```
hide names, emails and phone numbers
hide the salary and phone columns        (matches "Amount", "Mobile No", typos)
never send anything about my health
I don't want gemini to see my salary
keep my address private
Priya is private / never mention Project Falcon
block rows 2 to 5
redact anything containing Acme
Mumbai is fine                           (never flag it)
don't hide names / stop hiding the salary column
list rules / clear rules
```

Rules apply to your messages and the screen immediately, and to files you
attach afterwards. On spreadsheets and CSVs they run **before** the detectors,
because a rule can remove a whole column. They persist between sessions.

This parser runs locally and uses no model at all. That is a deliberate choice
rather than a shortcut: sending the instruction somewhere to be interpreted
would be slower, would need a network, and -- worse -- the instruction itself
usually names the sensitive thing. "Hide the Acme contract column" would leak
the very detail the rule exists to protect.

`hide names`, `hide addresses`, `hide companies` and `hide places` use the
text model, so they work on names and places that have no pattern.

---

## The one rule this is built around

Nothing reaches the server without passing through a single `sanitize()`
function. Typed text, extracted document text, OCR output and the screen
description all converge on it.

Then, immediately before transmission, the finished payload is scanned **a
second time**. If anything sensitive survived, the request is refused and
nothing is sent. A privacy guarantee that depends on every code path remembering
to be careful is not a guarantee; this one is enforced at the exit.

---

## Why the libraries live in a sandboxed page

Everything that parses untrusted input -- Transformers.js, ONNX Runtime,
pdf.js, SheetJS -- runs in `worker.html`, a sandboxed page with an opaque
origin. Its policy allows only the extension's own scripts and `blob:` URLs,
no `eval`, no inline script, and network access to **Hugging Face only**
(model weights). The libraries are vendored and hash-checked by the tests; the
side panel hands them to the sandbox, so nothing is web-accessible and no code
comes from a CDN.

The sandbox turns things into text and has no say in what counts as sensitive.
Detection and redaction happen in the side panel, afterwards.

Model files are cached by the side panel (`Cache Storage`, with
`unlimitedStorage`), because a sandboxed page has no storage that survives a
restart. After the first download, both models load from disk in a few
seconds. Settings has a button to delete them.

## Files

```
manifest.json     permissions, entry points, and the two security policies
background.js     service worker: routes messages, captures the screen
content.js        runs in the page: DOM scan, covers, page summary
lib/detect.js     checksums and pattern rules -- the shared detection core
lib/guard.js      the leak guard: every layer, levels, memory, exit check
lib/lexicon.js    the word lists the guard reasons with
lib/ner-align.js  maps the text model's word pieces back to characters
lib/rules.js      plain-language rules
lib/tables.js     rebuilds tables from OCR boxes
worker.html/.js   sandboxed extractor: both models, pdf.js, SheetJS
vendor/           pinned libraries, licences, hashes
sidepanel.*       the interface, the gate, review before sending
test/             run.js, guard.js, wiring.js -- `bash test/all.sh`
```

## Known gaps

Stated plainly rather than hidden.

- **The text model is English-first.** Names written in Devanagari or other
  scripts are not recognised; OCR of Devanagari is also poor.
- **Meaning-level leaks can still get through.** "I'm the only cardiologist
  in Jalna" identifies someone without containing a single private value.
  Health, religion, legal and money topics raise a warning, not a mask.
- **Logos are found only by their printed name** (Florence-2 base cannot
  locate them), so a logo labelled only in Devanagari may be missed.
- **Accuracy numbers come from our own labelled set**, not an independent
  benchmark.
- **Actions are limited to scroll and highlight**, and never happen without
  you pressing the button.
- **Large PDFs are capped** at six pages when read as images, and spreadsheets
  at 500 rows per sheet.
- **Tested in an emulation of the extension**, not by loading it into Chrome:
  the sandbox policy, library loading, model caching, both models and the
  side panel UI were exercised in a browser; the real extension context
  (tab capture, painting on real pages) needs a manual check.

## What to say when demonstrating it

Open a form with real-looking details. Press **Read this screen** — the values
disappear under black boxes. Switch to the **Sent** tab and read it aloud: the
labels are all there, the values are all placeholders.

Then ask a follow-up question and let the model answer correctly anyway. That is
the whole argument: structure is enough, values are not needed.

Then say the part most teams miss — the capture happens *after* the boxes are
painted, so an unredacted screenshot of the page never exists anywhere in the
extension.
