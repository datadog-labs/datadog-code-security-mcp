package main

// detectAuthMethod returns how authentication was configured for this MCP
// server process. The value is captured once in mcpAuthMethod at server
// startup (see runServer in start.go), before any tool call could mutate the
// environment by exporting resolved credentials — re-deriving it from the
// live environment on each call would misattribute that self-inflicted
// mutation as a user-set env var for every request after the first
// authenticated one.
func detectAuthMethod() string {
	return mcpAuthMethod
}
