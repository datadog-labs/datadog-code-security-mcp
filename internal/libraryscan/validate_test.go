package libraryscan

import (
	"testing"
)

func TestValidatePURL(t *testing.T) {
	tests := []struct {
		name    string
		purl    string
		wantErr bool
	}{
		{
			name:    "valid golang purl",
			purl:    "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
			wantErr: false,
		},
		{
			name:    "valid npm purl",
			purl:    "pkg:npm/lodash@4.17.21",
			wantErr: false,
		},
		{
			name:    "valid maven purl",
			purl:    "pkg:maven/com.cronutils/cron-utils@9.1.2",
			wantErr: false,
		},
		{
			name:    "empty string",
			purl:    "",
			wantErr: true,
		},
		{
			name:    "missing pkg: prefix",
			purl:    "npm/lodash@4.17.21",
			wantErr: true,
		},
		{
			name:    "bare package name",
			purl:    "lodash",
			wantErr: true,
		},
		{
			name:    "wrong prefix",
			purl:    "package:npm/lodash@4.17.21",
			wantErr: true,
		},
		{
			name:    "pkg: prefix only",
			purl:    "pkg:",
			wantErr: true,
		},
		{
			name:    "missing name",
			purl:    "pkg:npm",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePURL(tt.purl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePURL(%q) error = %v, wantErr %v", tt.purl, err, tt.wantErr)
			}
		})
	}
}
