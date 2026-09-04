package constants

// Environment variable names
const (
	EnvAPIKey     = "DD_API_KEY"
	EnvAPPKey     = "DD_APP_KEY"
	EnvSite       = "DD_SITE"
	EnvAuthDomain = "DD_AUTH_DOMAIN"
)

// Telemetry environment variable names
const (
	// EnvTelemetryDisabled disables telemetry when set to a truthy value (1, true, yes).
	EnvTelemetryDisabled = "DD_CODE_SECURITY_TELEMETRY_DISABLED"
	// EnvDoNotTrack respects the DO_NOT_TRACK standard (https://consoledonottrack.com/).
	EnvDoNotTrack = "DO_NOT_TRACK"
	// EnvTelemetryToken allows overriding the compiled-in client token at runtime (dev use only).
	EnvTelemetryToken = "DD_CODE_SECURITY_TELEMETRY_TOKEN"
	// EnvCI is the conventional flag CI systems set; its presence tags events as CI-originated.
	EnvCI = "CI"
)

// Telemetry payload constants
const (
	// TelemetryService is the service name sent in every telemetry log.
	TelemetryService = "datadog-code-security-mcp"
	// TelemetryDDSource identifies telemetry logs emitted by this application.
	TelemetryDDSource = "datadog-code-security-mcp"
	// TelemetryTeamTag identifies the team that owns the telemetry.
	TelemetryTeamTag = "team:k9-iac"
)

// Argument keys for MCP tool requests
const (
	ArgFilePaths   = "file_paths"
	ArgWorkingDir  = "working_dir"
	ArgMinSeverity = "min_severity"
	ArgPath        = "path"
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
