package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Detection records whether a client is available and why.
type Detection struct {
	Installed bool
	Reason    string
}

// IsInstalled applies the client detection policy: a matching CLI on PATH or a
// known user-home marker is sufficient.
func IsInstalled(client Client, homeDir string) (Detection, error) {
	for _, cliName := range client.CLINames {
		if _, err := exec.LookPath(cliName); err == nil {
			return Detection{Installed: true, Reason: fmt.Sprintf("%s found on PATH", cliName)}, nil
		}
	}

	for _, marker := range client.HomeMarkers {
		markerPath := filepath.Join(homeDir, marker)
		if _, err := os.Stat(markerPath); err == nil {
			return Detection{Installed: true, Reason: fmt.Sprintf("%s exists", markerPath)}, nil
		} else if !os.IsNotExist(err) {
			return Detection{}, fmt.Errorf("inspect %s marker %s: %w", client.DisplayName, markerPath, err)
		}
	}

	return Detection{
		Installed: false,
		Reason:    "client CLI and home markers were not found",
	}, nil
}
