# Version-controlled CVE source tree

`signatures/CVE-YYYY-NNNN/` is the single source of truth. CVE is the authoring
and maintenance unit; records are always owned by exactly one CVE.

- A CVE with only `research.json` has no machine-code database record yet.
- A CVE with `pack.json` and `rules-exec.yar` has one or more database records.
- Each record has a stable `record_id`, one `channel` (`test` or `production`),
  a platform, a source type, and one or more alternative machine patterns.

A CVE may own multiple DB records. A record belongs to exactly one CVE. If the
same byte pattern is useful for another CVE, it is intentionally copied into a
separate record under that CVE. The two records can be edited, moved between
channels, reviewed, or removed independently. There are no cross-CVE signature
associations or shared-signature identities.

`production` records are included in production releases. `test` records are
excluded from production releases and included in the test database. The test
database is a superset: it contains both production and test records so that
production detections remain covered by regression tests.

The channel controls inclusion, not evidence status. Source structure,
YARA-X compilation, integrity and platform checks are mandatory; detection
quality is investigated through per-record research and review (see
[Database](../docs/DATABASE.md)).

The libpng source tree currently has five CVEs with 25 production-channel
machine patterns, plus one research-only CVE without a machine record.
**The corpus roadmap is 100 distinct CVEs, then 1,000**, counted by CVEs with
production-channel machine records rather than by individual patterns.
Contributions to this corpus are the immediate priority; build variants and
platform backends are also welcome in parallel. See
[Contributing](../CONTRIBUTING.md) and the
[roadmap](../docs/ROADMAP.md).

The release builder compiles
every `production` record in the accepted Git tree. CI compiles both channels.
Inclusion is determined entirely by the two record channels.
