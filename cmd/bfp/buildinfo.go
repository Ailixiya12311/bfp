package main

// These variables are replaced by the release build script with -ldflags.
// Keeping safe defaults makes developer builds and tests self-describing.
var (
	buildVersion = "0.1.0-dev"
	buildCommit  = "uncommitted"
	buildDate    = "unknown"
)
