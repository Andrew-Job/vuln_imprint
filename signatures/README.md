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

The channel is an inclusion target, not a quality or correctness assertion.
A production record is not thereby independently proven to detect the named
CVE. Source structure, YARA-X compilation, integrity, and platform checks are
mandatory; detection correctness is assessed in separate research and review.

The current libpng source tree has five CVEs with 25 machine patterns, each
currently in the `production` channel, plus one research-only CVE without a
machine record. Those assignments make the records part of the current
production database; they do not certify their detection accuracy.

The release builder compiles
every `production` record in the accepted Git tree. CI compiles both channels.
Inclusion is determined entirely by the two record channels.
