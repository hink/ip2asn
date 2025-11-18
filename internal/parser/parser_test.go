package parser

import (
	"strings"
	"testing"
)

func TestParseIPsFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "basic ipv4",
			input: "hello 1.1.1.1 world",
			want:  []string{"1.1.1.1"},
		},
		{
			name:  "multiple ipv4",
			input: "1.1.1.1 8.8.8.8",
			want:  []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:  "ipv6 compressed",
			input: "2001:4860:4860::8888",
			want:  []string{"2001:4860:4860::8888"},
		},
		{
			name:  "duplicates",
			input: "1.1.1.1 1.1.1.1",
			want:  []string{"1.1.1.1"},
		},
		{
			name:  "invalid ipv4",
			input: "999.999.999.999",
			want:  []string{},
		},
        {
            name: "mixed valid and invalid",
            input: "192.168.1.1 and 300.300.300.300",
            want: []string{"192.168.1.1"},
        },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPsFromString(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("idx %d: got %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseIPs(t *testing.T) {
    input := "10.0.0.1\n10.0.0.2"
    r := strings.NewReader(input)
    got, err := ParseIPs(r)
    if err != nil {
        t.Fatalf("ParseIPs error: %v", err)
    }
    if len(got) != 2 {
        t.Errorf("expected 2 IPs, got %d", len(got))
    }
}
