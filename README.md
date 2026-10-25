# sd-vault

An encrypted folder for an SD card (exFAT). One Go binary per OS lives on
the card next to the data. Run it, type the password, and browse the files in
a local web UI: no installation, admin rights or FUSE driver needed.
User-facing instructions (Russian) are in [README-card.txt](README-card.txt);
`make` copies them to the card as `README.txt`.

## Build

```bash
make          # tests + dist/: vault-windows.exe, vault-macos (universal), vault-linux-{amd64,arm64}, README.txt
make test
```

Copy `dist/` to the card. The vault is created in `vault/` next to the
binary on first run (`-dir` overrides; `-no-browser`, `-port` also exist).
When stdin is not a terminal the password is read line by line from it, so
the binary can be scripted: `printf 'pw\npw\n' | ./vault-macos -no-browser`.

## Format

Everything on disk is a standard [age](https://age-encryption.org) file:

| file | content | encrypted to |
|---|---|---|
| `key.age` | X25519 identity (`AGE-SECRET-KEY-1…`) | password (scrypt) |
| `index.age` | JSON: entries with id, parent, name, size, blob path | the identity |
| `index.age.bak` | previous index | the identity |
| `blobs/ab/<128-bit id>.age` | one file's content | the identity |
| `packs/<128-bit id>.age` | small files back to back; the index has `pack`, `offset`, `size` | the identity |

The password unlocks only `key.age`, which is age's own
"passphrase-protected identity file" pattern. Scrypt runs once per unlock
instead of per file, and `age.DecryptReaderAt` gives random access into big
files, so video seeking via HTTP Range does not decrypt the whole file.
The age CLI reads such identity files natively:
`age -d -i vault/key.age vault/blobs/…`; a packed file is the slice
`[offset, offset+size)` of the decrypted pack. `TestStandardAgeCLI` checks
both with the official binaries.

### Packs

On a card the cost of a file is its creation, not its bytes: FAT entries, an
fsync, and on macOS an AppleDouble `._` companion that holds the
`com.apple.provenance` attribute. So a batch upload (`PutDeferred`) gathers
files up to 1 MiB in memory and writes them as one pack once it reaches
8 MiB or on the next commit; until then its members are served from memory.
Bigger files keep a blob each. Packs are age files like blobs, and the 64 KiB
STREAM chunks keep random access into them. A pack is removed when its last
member is deleted or replaced; space of removed members inside a live pack
is not reclaimed (only files up to 1 MiB are packed, so that stays small).
Index version 2 marks the format; older programs cannot read packed files.
Existing blobs stay as they are.

On the 2 GB test card, 200 files of 10 KB took 190 s with a blob each and
5.4 s packed, and the next unlock 7.4 s and 0.5 s.

## Durability

Every write goes to a temp file in the same directory, then rename. Index
and key writes, and blobs of immediate puts, are fsynced before the rename
and the directory after it (where the OS allows it). Batch uploads write
packs and blobs without fsync; the commit that first names them in the
index syncs them all first, one fsync per batch instead of per file, so the
index on disk never points at content a pulled card could lose. Mkdir, rename and delete save
the index before returning. Uploads from the UI (`batch=1`) change it only in
memory: it is written once on `/api/flush` after the upload queue, after 3 s
without uploads, at least every 30 s, and on close. A card pulled mid-batch
loses only the unflushed uploads; their blobs and packs are swept as orphans.
Replaced content is removed only after the index stops naming it. The index is
compact JSON. "Проверить сейф" (`POST /api/verify`, polled via `GET`) decrypts
every blob and pack to the end in the background and lists the files that
fail authentication or are missing; in a pack with a bad chunk only the
members in that chunk are reported. The index rotates to
`index.age.bak` on save; if `index.age` is missing or fails authentication,
the backup is loaded and written back. Blobs are removed only after the index
stops referencing them; orphans and temp files are swept on the next unlock
(only when the primary index loaded, so a fallback never deletes data). The
sweep leaves `._*` files alone: they are macOS's, it removes each with its
file, and deleting 4400 of them one by one once kept an unlock busy for six
minutes.

## Updates and releases

On start, when stdin is a terminal and `-no-update` is not set, the program
asks the GitHub API for the latest release of `kirvigen/sd-vault` (4 s
timeout; offline means no question). A newer `vX.Y.Z` is offered with its
notes; on "д" every program already on the card is replaced, plus the
running one whatever its name, and the program restarts (`exec` on Unix, a
child process on Windows). Dev builds (`git describe` not an exact tag) never
update.

Trust does not come from GitHub. Each release carries `release.txt`
(`sd-vault vX.Y.Z` plus sha256 lines) and `release.txt.sig`, an ed25519
signature checked against `update.PublicKey`. The version line stops an old
signed manifest from being replayed under a new tag. Before downloading,
the free space next to the program is checked against the sizes GitHub
reports (all new files sit next to the old ones until the swap); a full card
is refused at once with how much to free, instead of failing on the last
file minutes later. All files are
downloaded to `*.new` and verified before any rename; the running program is
renamed to `*.old` (Windows allows that), and leftovers are removed on the
next start.

The private key is `~/.config/sd-vault/release.key` and never goes into the
repo. **Back it up**: without it no further update can be signed, and the
cards in use would need a manual upgrade to a build with a new key.

```bash
make release VERSION=v1.1.0 NOTES="Что нового"
```

builds, signs, tags, pushes and runs `gh release create`.

## Security notes

- HTTP on `127.0.0.1`, random port. A one-time token in the URL is traded
  for an HttpOnly, SameSite=Strict cookie. Host header is checked (DNS
  rebinding), foreign `Origin` on POST is refused.
- Uploads stream the raw request body into the encryptor. No multipart
  parsing, because Go's multipart code spills large parts to a plaintext temp file.
- Responses are `Cache-Control: no-store`. Stored HTML/JS/XML is served
  as `text/plain`, and every inline file except PDF gets `CSP: sandbox`.
- "Key wiped" is best effort: `Close` drops the identity and the index and
  runs the GC. Go cannot guarantee zeroing (strings, copies made by the age
  library), and the OS may swap. "Download" leaves a plaintext copy on the
  host computer by design, and the card README says so.
