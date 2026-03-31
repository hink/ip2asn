package main

import (
	"testing"

	"ip2asn/internal/output"
)

func TestValidateTUIOptions(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		format    string
		outPath   string
		stdinTTY  bool
		stdoutTTY bool
		wantErr   bool
	}{
		{
			name:      "disabled",
			enabled:   false,
			format:    "table",
			stdinTTY:  false,
			stdoutTTY: false,
			wantErr:   false,
		},
		{
			name:      "table tty ok",
			enabled:   true,
			format:    "table",
			stdinTTY:  true,
			stdoutTTY: true,
			wantErr:   false,
		},
		{
			name:      "json rejected",
			enabled:   true,
			format:    "json",
			stdinTTY:  true,
			stdoutTTY: true,
			wantErr:   true,
		},
		{
			name:      "csv rejected",
			enabled:   true,
			format:    "csv",
			stdinTTY:  true,
			stdoutTTY: true,
			wantErr:   true,
		},
		{
			name:      "output path rejected",
			enabled:   true,
			format:    "table",
			outPath:   "out.txt",
			stdinTTY:  true,
			stdoutTTY: true,
			wantErr:   true,
		},
		{
			name:      "stdin non tty rejected",
			enabled:   true,
			format:    "table",
			stdinTTY:  false,
			stdoutTTY: true,
			wantErr:   true,
		},
		{
			name:      "stdout non tty rejected",
			enabled:   true,
			format:    "table",
			stdinTTY:  true,
			stdoutTTY: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTUIOptions(tt.enabled, tt.format, tt.outPath, tt.stdinTTY, tt.stdoutTTY)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateTUIOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChooseTableMode(t *testing.T) {
	tests := []struct {
		name          string
		enrichEnabled bool
		want          output.TableMode
	}{
		{
			name:          "basic mode",
			enrichEnabled: false,
			want:          output.TableModeBasic,
		},
		{
			name:          "proxycheck mode",
			enrichEnabled: true,
			want:          output.TableModeProxycheck,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chooseTableMode(tt.enrichEnabled); got != tt.want {
				t.Fatalf("chooseTableMode() = %v, want %v", got, tt.want)
			}
		})
	}
}
