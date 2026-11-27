# Contributed lines for Manuscribe's recognition models

Manuscribe reads manuscript pages with recognition models that run in the browser. The models read better when they
learn from pages that people have read and corrected. This repository is where editors who agree send the corrected
lines of a manuscript, and its folio sides whose blocks they have drawn and counted, so that the next models can learn
from them: the line recogniser from the lines, the line segmenter from the sides.

**Languages and scripts are kept apart.** Every contribution states the manuscript's language and script (a tag as
`sa-Deva`, Sanskrit in Devanagari), and is registered and released under it; the models of one language and script
learn from its contributions only.

Nothing here is sent automatically, and nothing is contributed without the editor's yes for that manuscript.

## Sending lines (for editors)

1. In Manuscribe, read folio sides with **⚡ Recognise** (on the scan's toolbar, or the Folio tab), and correct and
   accept the lines.
2. In the Manuscript tab, answer the question about training (Settings › Recognition asks it, if you tick that you
   wish to be asked). A yes needs the right to share the images confirmed.
3. **Contribute corrected lines…** saves a file, `manuscribe-contribution-c….zip`, and opens a new issue here with its
   form filled in. Drag the file into the **Sealed package** box and submit. With the consent of wording 3 the file
   also holds the folio sides whose blocks you drew on that side itself (Calibrate; not a calibration applied from
   another side) and whose every block holds as many lines of text as you gave it: they teach the segmenter.
4. A bot answers on the issue within a few minutes: the package is registered, or it says what is wrong.

**What is public and what is not.** The issue is public: it shows the manuscript's name as you gave it, its language
and script, the number of lines and folio sides, the date and wording of your consent, and your GitHub account. The
lines and sides themselves (their images and texts) are sealed in the file: they are encrypted to the maintainer's
key, and only the maintainer can open them. Folio sides are taken only on a consent that gives them (wording 3). The
sealed files are kept in a draft release that only the maintainer sees.

**Withdrawing.** Manuscribe's **Withdraw…** (Manuscript tab) opens a "Withdraw contributed lines" issue naming the
packages; you can also open one yourself, naming the package ids (`c20261124-…`) or the issues the lines came in
(`#12`). The bot withdraws at once the lines sent from your own GitHub account; lines sent from another account wait
for the maintainer. Withdrawn lines are deleted here and left out of every model trained afterwards. Models already
trained on them while the consent was given remain, and are not withdrawn. Without a GitHub account, write to
drdhaval2785@gmail.com with the package ids.

## What the bot does

`.github/workflows/inbox.yml` runs `tools/inbox.py` on every issue opened or edited.

- **A contribution.** It fetches each attached file and takes it only if it is a sealed package from Manuscribe that
  is whole (its checksum and id are what it says), was sealed to a key that `approved.json` lists, and carries a
  consent that says yes, confirms the right to share the images, is not withdrawn, and was given on a wording that
  `approved.json` lists; inside the seal, every folio side's image and blocks must be there, its blocks drawn on that
  side itself. A package taken is kept as an asset of the draft release `packages-<year>`, registered in
  `register.tsv`, and answered; the issue is closed. A package refused is answered with the reasons.
- **A withdrawal.** It deletes the named packages' assets and marks their rows withdrawn (rows are kept, so that a
  model's card can say what it no longer learns from).
- **A data release** follows every change: `data-<date>-<time>`, with `dataset.json` (the packages training may use
  from then on, and those withdrawn) and `register.tsv` as it stood. A model's card names the data release it was
  trained from.

If the private key is a secret here (`CONTRIBUTION_KEY`), the bot also opens the lines to check them, and forgets
them; without it, the lines are opened only on the maintainer's computer.

## Files

- `register.tsv`: a row per package (id, issue, GitHub account, manuscript, language and script, lines, folio sides,
  consent wording and date, state).
- `approved.json`: the consent wordings taken (Manuscribe's `CONSENT.version`), those of them that give folio sides,
  and the ids of the maintainer's keys.
- `tools/inbox.py`: the bot (Python's standard library, and `cryptography` only to open lines).
- `tests/test_inbox.py`: the bot without GitHub: `python -m pip install cryptography`, then
  `python -m unittest discover -s tests -v`.

## For the maintainer

Once, when this repository is made:

1. Create the public repository `drdhaval2785/manuscribe-contributions` on GitHub and push this folder.
2. Run **Actions › Maintain › Run workflow** with `labels`: it makes the labels the issue forms apply. Issues made
   before that are still recognised by their forms, but do this first.
3. Leave immutable releases off in the repository's settings: a withdrawal deletes an asset of the draft release
   (drafts can be changed even with it on, but the data releases are published ones).
4. If you wish the bot to open and check the lines too, add the private key as the secret `CONTRIBUTION_KEY`
   (Settings › Secrets and variables › Actions): the contents of `~/.config/manuscribe/contribution-key.pem`. Without
   it, the lines never leave your computer unsealed.

The key: made once on the maintainer's computer by
[devanagari-manuscript-ocr](https://github.com/drdhaval2785/devanagari-manuscript-ocr) (`python -m msocr.seal keygen`). The private key
stays at `~/.config/manuscribe/contribution-key.pem`; **keep a copy somewhere safe**, since the lines sealed to it open
with nothing else. The public key goes on the models' site (`python -m msocr.site` writes `contribute.json`), where
Manuscribe fetches it.

To train with the lines: `python -m msocr.contributions sync` (in devanagari-manuscript-ocr, signed in to `gh`) fetches the
packages registered here and not yet there, opens them, checks every line (`msocr/linequality.py`: lines that fail are
left out, a package with too many failures is quarantined until `contributions accept <id>`), and withdraws there what
was withdrawn here; `python -m msocr.recognizer pool` then trains on the lines that passed, guarded so that they cannot
make the model read the developer's own manuscripts worse, and the model's card names the packages and data release.

Wordings 1 and 2 (24 November 2026) told contributors the models are published under CC BY-SA 4.0; since 27
November 2026 the segmenter and the recogniser are CC BY-NC-SA 4.0, so only wording 3, which says so, is taken (no
package had been given on 1 or 2).

A new consent wording: change it in Manuscribe (a new `CONSENT.version`), then add the version to `approved.json` here
and to `APPROVED` in devanagari-manuscript-ocr's `msocr/contributions.py`, and run `python -m msocr.site` so that the site's
`contribute.json` lists it.

A withdrawal received by e-mail: open a "Withdraw contributed lines" issue yourself with the ids; as the owner, the bot
takes it from you. To withdraw lines sent by another account on their behalf, add the label `withdrawal-confirmed` to
their withdrawal issue.

Version 0.13.3, with Manuscribe 0.13.3 (Manuscribe and its companions always carry the same version number). The code is under the GNU GPL v3 (LICENSE), as Manuscribe's.
