// Package skills embeds the Datadog Code Security skills shipped with the CLI.
package skills

import "embed"

// FS holds the skills shipped with this release. Adding a dd-codesec-*
// directory automatically includes its complete subtree in the binary.
//
//go:embed dd-codesec-*
var FS embed.FS
