# Changelog

## Validation hardening
- Fixed multi-account investigation filtering so related events include every username associated with an alert.
- Added clear validation errors for empty CSV files, malformed CSV parsing, and datasets without valid timestamps.
- Added offline regression tests for all four detection rules, sample data, related-event matching, invalid uploads, and report contents.
