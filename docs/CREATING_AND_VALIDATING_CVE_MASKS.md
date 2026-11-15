# Create and validate a CVE machine-code signature

Create one CVE-owned directory, `signatures/CVE-YYYY-NNNN/`, containing
`pack.json` and `rules-exec.yar`. Supported target: Linux ELF64 x86-64.
A match identifies a compiled code form, not whether the vulnerable path can be
reached or exploited in an application.

## 1. Identify the patch

Read the CVE advisory, the complete upstream fix and any follow-up corrections.
Identify the affected function, unsafe operation, missing guard and corrected
behavior. Record exact source revisions and relevant backports. Choose an
**affected** build containing the unfixed machine code and a **fixed** build
containing the complete correction; intermediate commits may require a separate
classification. Verify compiled code and build features rather than using
version strings as ground truth. Distinguish code presence from runtime
reachability.

## 2. Obtain the binary pair

Use either route; both continue at step 3.

**A — Ready-made binaries.** Retrieve `.so` files or executables from upstream
release archives, Debian/RPM packages, Python wheels or container images.
Extract them without modifying their machine code (`dpkg-deb -x` for `.deb`,
`rpm2cpio | cpio` for `.rpm`, `unzip` for wheels). Confirm their ELF type and
record their package origin, SHA-256 and exact build configuration.

**B — Source-built binaries.** Check out affected and fully fixed revisions
into separate clean directories. Use the component's normal build procedure
with comparable compiler, optimization and feature flags; retain the ELF files
and record source SHAs, build commands, compiler versions and SHA-256. For
statically linked code, link a host against the component archive and confirm
that the target function is present in its executable ranges. A new build must
not silently reuse binaries or reports from an earlier run.

```bash
file vulnerable.so fixed.so
sha256sum vulnerable.so fixed.so
readelf -Ws vulnerable.so | grep 'FUNCTION_NAME'
readelf -Ws fixed.so | grep 'FUNCTION_NAME'
```

Separate discovery samples used to choose or refine a mask from validation
samples held out until the mask is fixed. Include affected, fully fixed, genuine
backport and unrelated ELF controls where available. Feature-disabled builds
are negative controls only when the vulnerable code was not compiled; unreachable
but still present machine code is not automatically a false positive. Different
ELF hashes or link layouts with identical relevant instructions do not establish
independent machine-code forms. A compiler/optimization form is not validated
independently merely because the same build was stripped or relinked.

## 3. Extract the vulnerable instructions

```bash
objdump -drwC vulnerable.so > vulnerable.asm
objdump -drwC fixed.so > fixed.asm
```

Follow the patch from source statements to the affected and fixed control
flow and data flow. DWARF line mappings (`objdump -dSl`) help locate code but
are not proof: optimizations may move or inline instructions. Identify the
unsafe calculation and the corresponding guard or corrected operation. For
stripped binaries, use
[Ghidra](https://github.com/NationalSecurityAgency/ghidra),
[BinExport](https://github.com/google/binexport) +
[BinDiff](https://github.com/google/bindiff), or
[VxSig](https://github.com/google/vxsig) to propose candidate locations; review each
candidate against the upstream patch. Do not accept the first window absent
from fixed binaries solely because it has enough fixed bytes. Select whole
instructions that characterize the vulnerable computation, and document how
its inputs reach the unsafe operation and its sink. Review conditional branches
and reject accidental sequences spanning dead padding or unrelated blocks.
A manually selected interval is acceptable; its semantic correctness cannot
be established by checking that an evidence JSON contains an explanation.
Bind the patch-to-instruction mapping to the source and binary hashes.
Addresses are outputs of this localization, not portable selectors.

For a manually reviewed patch-guided window, the existing Factory API converts
whole instructions to a normalized hex mask. Replace the ELF path, symbol, and
**VA** interval with those established for that exact binary:

```python
from pathlib import Path
from factory.disasm import disassemble

elf = Path('work/vulnerable.so')
start, end = 0x1000, 0x1040  # illustrative: replace with reviewed ELF VAs
ins = [i for i in disassemble(elf, ['FUNCTION_NAME'])
       if start <= i.va < end]
if (not ins or ins[0].va != start or
    any(a.va + len(a.raw) != b.va for a, b in zip(ins, ins[1:])) or
    ins[-1].va + len(ins[-1].raw) != end):
    raise ValueError('window is not contiguous, instruction-aligned code')
Path('work').mkdir(exist_ok=True)
Path('work/mask.hex').write_text(
    ' '.join(i.normalized.to_hex() for i in ins) + '\n')
```

This checks instruction boundaries, **not** semantics. Review the decoded
instructions and actual control-flow edges separately; all selected bytes must
belong to the intended source-derived operation. Do not assume a fixed build
cannot retain the same window behind a newly added guard. Record such
backport limitations explicitly and use real fixed/backport controls.

Use the existing Factory disassembler/normalizer to obtain a space-separated
YARA-X hex pattern. Wildcard relocation, address and relative branch/call
displacements as needed, without wildcarding the instructions essential to
the vulnerability. Inspect the decoded bytes and execution edges after
normalization. Save the chosen pattern to `work/mask.hex`. Each pattern must
have at least **28 bytes, including 24 fixed bytes**. Add separate masks for
distinct vulnerable machine-code forms rather than widening one mask until
it matches unrelated code. If the component has Unicode or wide-character
build modes, inspect each affected code form separately; a YARA string
`wide` modifier does not turn a machine-code mask into a wide-character variant.

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

Require `PASS_PRELIMINARY` for the explicitly claimed machine-code profile:
hits in the affected controls, no hits in fixed/backported/unrelated controls,
and offsets within the vulnerable function. Review every alternative pattern
against all negative controls: a record matches when **any** of its patterns
matches, even if a different pattern was designed for that compiler. Search **executable ELF ranges**,
not the complete file or debug/data sections. Keep the full exploratory matrix
including any FN; report unsupported compiler/optimization forms rather than
removing them from the results or weakening the mask to force coverage.
Independently validate the frozen mask on held-out binaries. If a holdout is
used to adjust the mask, it becomes a discovery sample. Preliminary screening
is not native YARA-X/Scanner acceptance.

## 5. Add the CVE record

```bash
python -m tools.manual_rules init --cve "$CVE" \
  --record-key vulnerable-variant --channel test --hex "$MASK" \
  --output "signatures/$CVE"
python -m tools.manual_rules lint --directory "signatures/$CVE"
python -m tools.binary_samples --cve "$CVE" \
  --pack "signatures/$CVE/pack.json" \
  --samples "work/$CVE.samples.json" --output "work/$CVE.pack-screen.json"
```

Repeat `--hex` in `init` to add alternative patterns within this record.
For an existing CVE, retain its `record_id` and regenerate the canonical rule
source as described in [Database](DATABASE.md).

## 6. Verify and commit

Use the native Scanner with the assembled database on affected, fixed and
held-out control ELF files. Check actual CVE, `record_id`, pattern IDs and
**file offsets**, not merely whether any rule matched. Preserve SHA-256,
TP/TN/FP/FN and native command logs. Only select `production` for a record whose
claimed machine-code profile and limitations are supported by the evidence;
channel assignment does not prove detection correctness or exploitability.
GitHub Actions validates native integration and release database consistency.

Commit only the production `pack.json` and canonical `rules-exec.yar` for a
new detection. Record the vulnerability-specific fix, supported machine-code
forms, affected/fixed sample SHA-256, match offsets and known limitations in
the CVE record `notes`. Retain the full sample matrix and reproduction logs
for reviewer verification outside the product source tree; do not commit
specimen binaries or investigation artifacts. The reviewer must be able to
reproduce the positive and negative observations before admitting a record to
`production`.
