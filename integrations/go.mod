module bfp-integration-snapshots

go 1.26.0

// The directories below are frozen Mihomo/sing-box source snapshots and
// validation fixtures. They are intentionally a nested module so the root
// BFP product build does not try to compile a snapshot against the upstream
// module's private dependency graph. Integration builds are run from their
// own pinned source checkout and evidence directory.
