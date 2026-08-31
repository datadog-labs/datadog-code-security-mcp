package setup

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Client describes an AI coding client that can consume user-level skills.
type Client struct {
	ID                string
	DisplayName       string
	CLINames          []string
	HomeMarkers       []string
	SkillsDirSegments []string
}

var supportedClients = []Client{
	{
		ID:                "claude-code",
		DisplayName:       "Claude Code",
		CLINames:          []string{"claude"},
		HomeMarkers:       []string{".claude"},
		SkillsDirSegments: []string{".claude", "skills"},
	},
	{
		ID:                "cursor",
		DisplayName:       "Cursor",
		CLINames:          []string{"cursor", "cursor-agent"},
		HomeMarkers:       []string{".cursor"},
		SkillsDirSegments: []string{".cursor", "skills"},
	},
	{
		ID:                "codex",
		DisplayName:       "Codex",
		CLINames:          []string{"codex"},
		HomeMarkers:       []string{".codex"},
		SkillsDirSegments: []string{".codex", "skills"},
	},
}

// Clients returns a copy of the supported client registry.
func Clients() []Client {
	clients := make([]Client, len(supportedClients))
	copy(clients, supportedClients)
	return clients
}

// ClientByID returns the supported client with the given stable ID.
func ClientByID(id string) (Client, error) {
	validIDs := make([]string, 0, len(supportedClients))
	for _, client := range supportedClients {
		if client.ID == id {
			return client, nil
		}
		validIDs = append(validIDs, client.ID)
	}
	return Client{}, fmt.Errorf("unsupported client %q (valid options: %s)", id, strings.Join(validIDs, ", "))
}

// SkillsDir resolves the client's user-level skills directory.
func (c Client) SkillsDir(homeDir string) string {
	segments := append([]string{homeDir}, c.SkillsDirSegments...)
	return filepath.Join(segments...)
}
