# Create and validate a CVE machine-code signature

Create one CVE-owned directory, `signatures/CVE-YYYY-NNNN/`, containing
`pack.json` and `rules-exec.yar`. Supported target: Linux ELF64 x86-64.

## 1. Identify the patch

Read the CVE advisory and the complete upstream fix. Identify the affected
function, vulnerable operation and exact corrected behavior. Record the fix
commit and any vendor backport. Select an **unfixed** and a **fixed** build
containing this function. Determine their status from the actual compiled
instructions, not from the package version alone.

## 2. Obtain the binary pair

Use either route; both continue at step 3.

**A — Ready-made binaries.** Retrieve `.so` files or executables from upstream
release archives, Debian/RPM packages, Python wheels or container images.
Extract them without modifying their machine code (`dpkg-deb -x` for `.deb`,
`rpm2cpio | cpio` for `.rpm`, `unzip` for wheels). Confirm their ELF type and
record their package origin and SHA-256.

**B — Source-built binaries.** Check out the revision before the *entire* fix
and the revision after it. Build with comparable compiler/feature flags, retain
the vulnerable and fixed ELF files, and record commit SHAs, build commands,
compiler versions and SHA-256.

```bash
file vulnerable.so fixed.so
sha256sum vulnerable.so fixed.so
readelf -Ws vulnerable.so | grep 'FUNCTION_NAME'
readelf -Ws fixed.so | grep 'FUNCTION_NAME'
```

Prepare additional independent affected, fixed/backported and unrelated ELF
controls when available.

## 3. Extract the vulnerable instructions

```bash
objdump -drwC vulnerable.so > vulnerable.asm
objdump -drwC fixed.so > fixed.asm
```

Locate the changed function in both disassemblies and isolate an instruction
sequence describing the **unfixed** code path. For complex changes, use
[Ghidra](https://github.com/NationalSecurityAgency/ghidra),
[BinExport](https://github.com/google/binexport) +
[BinDiff](https://github.com/google/bindiff), or
[VxSig](https://github.com/google/vxsig) to propose byte windows; review each
candidate against the upstream patch.

Write a space-separated YARA-X hex pattern to `work/mask.hex`. Replace
variable relocation, address and branch-displacement bytes with `??` without
removing the instructions that distinguish the vulnerable code. Each pattern
must have at least **28 bytes, including 24 fixed bytes**. Add separate masks
for distinct compiled vulnerable forms.

## 4. Screen the masks on real ELF controls

Create `work/CVE-YYYY-NNNN.samples.json`:

```json
{
  "schema_version": 1,
  "cve": "CVE-YYYY-NNNN",
  "samples": [
    {"id":"v1","path":"/absolute/vulnerable.so","sha256":"ACTUAL_SHA256","label":"affected","origin":"package/build source","label_basis":"unfixed path verified in FUNCTION_NAME"},
    {"id":"f1","path":"/absolute/fixed.so","sha256":"ACTUAL_SHA256","label":"fixed","origin":"package/build source","label_basis":"fixed instructions verified in FUNCTION_NAME"},
    {"id":"u1","path":"/absolute/unrelated.so","sha256":"ACTUAL_SHA256","label":"unrelated","origin":"package/build source","label_basis":"unrelated component"}
  ]
}
```

From the repository root, replace the example CVE with your chosen ID:

```bash
CVE=CVE-YYYY-NNNN
MASK="$(cat work/mask.hex)"
python -m tools.binary_samples --cve "$CVE" --hex "$MASK" \
  --samples "work/$CVE.samples.json" --output "work/$CVE.screen.json"
```

Require `PASS_PRELIMINARY`: a hit in every declared affected sample, no hit in
fixed/backported/unrelated samples, and match offsets inside the relevant
function. Add another mask or narrow its claimed build profile when necessary.
This is a reference executable-segment screen; native YARA-X/Scanner tests
remain a separate validation step.

## 5. Add the CVE record

```bash
python -m tools.manual_rules init --cve "$CVE" \
  --record-key vulnerable-variant --channel test --hex "$MASK" \
  --output "signatures/$CVE"
python -m tools.manual_rules lint --directory "signatures/$CVE"
python -m scripts.check_cve_source_tree
python -m tools.binary_samples --cve "$CVE" \
  --pack "signatures/$CVE/pack.json" \
  --samples "work/$CVE.samples.json" --output "work/$CVE.pack-screen.json"
```

Repeat `--hex` in `init` to add alternative patterns within this record.
For an existing CVE, retain its `record_id` and regenerate the canonical rule
source as described in [Database](DATABASE.md).

## 6. Verify and commit

Use the native Scanner to test the compiled rules against the full sample
matrix. Save the CVE ID, `record_id`, pattern IDs, SHA-256, file offsets,
TP/TN/FP/FN and command logs. Run repository tests and the **review → assemble
→ verify** workflow in [Database](DATABASE.md#review-and-assembly). Set the
record's channel to `production` when selecting it for the release database;
repeat lint, assembly and verification after the change. The channel determines
inclusion, **not** the evidence quality.

Commit `pack.json`, `rules-exec.yar`, SHA-pinned sample manifest and validation
evidence. Keep third-party binary blobs out of Git unless redistribution is
licensed. The [0.1.1 real-ELF examples](research/binary-first-0.1.1/README.md)
show the resulting structure, patch-to-instruction mapping and observations.
