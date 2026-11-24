"""Review an explicit list of local files and export only that list."""
import argparse
from pathlib import Path
import re
import sys
from zipfile import ZIP_DEFLATED, ZipFile

RULES = {
    "private key": rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    "GitHub token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "AWS access key ID": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "Google API key": rb"\bAIza[A-Za-z0-9_-]{35}\b",
    "possible API secret": rb"\bsk-[A-Za-z0-9_-]{20,}",
}
MAX_SIZE = 8 * 1024 * 1024
MAX_TOTAL_SIZE = 64 * 1024 * 1024


def collect(root, names):
    payload = {}
    findings = []
    total_size = 0
    for name in names:
        relative = Path(name)
        if relative.anchor or '..' in relative.parts or not relative.parts or ':' in name:
            raise ValueError("Use file paths relative to the project root.")
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink() or current.is_junction():
                raise ValueError("Symbolic links and junctions cannot be exported.")
        if not current.is_file() or not current.resolve().is_relative_to(root):
            raise ValueError("Each selected path must be a file inside the project.")
        if current.stat().st_size > MAX_SIZE:
            raise ValueError("Selected files may be at most 8 MiB each.")
        label = relative.as_posix()
        if label in payload:
            continue
        with current.open('rb') as stream:
            data = stream.read(MAX_SIZE + 1)
        if len(data) > MAX_SIZE:
            raise ValueError("Selected files may be at most 8 MiB each.")
        total_size += len(data)
        if total_size > MAX_TOTAL_SIZE:
            raise ValueError("The selected files may total at most 64 MiB.")
        payload[label] = data
        lower = current.name.lower()
        if (lower == '.env' or lower.startswith('.env.') or lower in {'.npmrc', '.netrc', 'id_rsa', 'id_ed25519'}
                or current.suffix.lower() in {'.key', '.pem', '.pfx', '.p12'}
                or '.git' in (part.lower() for part in relative.parts)):
            findings.append((label, 'sensitive path'))
        try:
            data.decode('utf-8')
            if b'\0' in data:
                raise ValueError()
        except ValueError:
            findings.append((label, 'not supported as UTF-8 text'))
        for kind, pattern in RULES.items():
            if re.search(pattern, data):
                findings.append((label, kind))
    return payload, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', help='Exact relative paths to review')
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, help='Write a new ZIP only if checks pass')
    args = parser.parse_args()
    try:
        payload, findings = collect(args.root.resolve(strict=True), args.files)
        for label in payload:
            print(f'Selected: {label!r}')
        for label, kind in findings:
            print(f'Blocked: {label!r} ({kind})')
        if findings:
            return 1
        if args.output:
            with ZipFile(args.output, 'x', compression=ZIP_DEFLATED) as archive:
                for label, data in payload.items():
                    archive.writestr(label, data)
            print(f'Created ZIP with {len(payload)} file(s).')
        return 0
    except ValueError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2
    except OSError:
        print('Error: Check file permissions and choose a ZIP destination that does not exist.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
