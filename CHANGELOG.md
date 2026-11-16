# 2.1.0 (TBD)

 * Move to Go 1.22
 * Normalize analysis results once so JSON, JUnit and the exit code always share the same deduplicated advisory set
 * Make JUnit report one testcase per advisory, with tests/failures matching the advisory count
 * Fail with exit code 127 instead of silently ignoring formatter errors (including the GitHub `raw_json` output)

# 2.0.0 (2022-04-09)

 * Add --cache-dir
 * Add --disable-exit-code
 * Move to Go 1.18

# 1.2.0 (2021-09-21)

 * Add --no-dev

# 1.1.0 (2021-08-31)

 * Add an example about how to use the tool in a cron
 * Add junit formatting
 * Be more lenient with non-standard pre-release versions (alpha12 -> alpha.12)
 * Add support for RC releases and make rc/beta/alpha non case-sensitive
 * Handle path prefixed with tilde sign ~
 * Add the --archive flag
 * Move to Go 1.17

# 1.0.0 (2020-01-13)

 * Initial release
