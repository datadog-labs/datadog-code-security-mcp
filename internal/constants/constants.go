package constants

// Environment variable names
const (
	EnvAPIKey     = "DD_API_KEY"
	EnvAPPKey     = "DD_APP_KEY"
	EnvSite       = "DD_SITE"
	EnvAuthDomain = "DD_AUTH_DOMAIN"
)

// Argument keys for MCP tool requests
const (
	ArgFilePaths  = "file_paths"
	ArgWorkingDir = "working_dir"
	ArgPath       = "path"
)

// Default values
const (
	DefaultWorkingDir = "."
	DefaultScanPath   = "."
)

// Error messages
const (
	ErrInvalidArguments = "invalid arguments format"
	ErrAuthRequired     = "Authentication required but failed"
	ErrAPIKeyRequired   = "DD_API_KEY is required to fetch security rules"
)

// Authentication instruction messages
const (
	AuthInstructionDDAuth = `For Datadog employees, configure with dd-auth:
  claude mcp add datadog-code-security -e DD_AUTH_DOMAIN=app.datadoghq.com -- datadog-code-security-mcp start`

	AuthInstructionAPIKey = `Or set DD_API_KEY directly:
  claude mcp add datadog-code-security -e DD_API_KEY=<key> -e DD_APP_KEY=<app-key> -e DD_SITE=datadoghq.com -- datadog-code-security-mcp start`
)
