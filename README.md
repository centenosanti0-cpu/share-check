# Share Check

Review the exact files you plan to send and build a ZIP from that selection. Share Check runs locally with Python 3.12 or newer and needs no packages, accounts, or API keys.

## Review first

From the folder containing `share_check.py`, point the tool at your project and list the files you intend to share:

```sh
python share_check.py --root ./my-project src/app.py "docs/Getting Started.txt"
```

The report lists your selection and any blocked paths or recognized credential patterns. It shows the file name and the type of finding without printing the matched value. Unlisted files are never read or added.

## Export

Run the same command with an output filename after reviewing the selection:

```sh
python share_check.py --root ./my-project src/app.py "docs/Getting Started.txt" --output ./client-share.zip
```

The export checks the selection again and writes the bytes it checked. A finding blocks the whole export. An existing ZIP is never overwritten. Open the resulting ZIP and confirm its file list before sending it.

Exit codes: `0` passed, `1` blocked by a finding, `2` invalid selection or I/O error.

The tool accepts UTF-8 text only, up to 8 MiB per file and 64 MiB total. It blocks common sensitive filenames and checks for several common token and private key formats. Passwords in ordinary text, personal information and unknown credential formats may pass. Review the content before sharing.
