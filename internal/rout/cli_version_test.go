package rout

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCLIVersionAliasesDoNotLoadOrChangeConfiguration(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	invalid := []byte("deliberately unreadable as JSON; version must not load settings")
	if e := os.WriteFile(settings, invalid, 0600); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{
		{"version"}, {"--version"}, {"-v"},
		{"--lang", "en", "--version"}, {"-v", "--lang", "zh-CN"},
		{"list", "--version"},
	} {
		t.Run(args[0]+"/"+itoa(len(args)), func(t *testing.T) {
			// Equal home/bin paths would fail ordinary command validation. Neither
			// path validation, settings reads, root checks nor service actions apply.
			args = append(append([]string{}, args...), "--home", dir, "--bin-dir", dir)
			output, e := os.CreateTemp(t.TempDir(), "stdout")
			if e != nil {
				t.Fatal(e)
			}
			defer output.Close()
			original := os.Stdout
			defer func() { os.Stdout = original }()
			os.Stdout = output
			err := Run(args)
			os.Stdout = original
			if _, e = output.Seek(0, 0); e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(output)
			if e != nil || err != nil || string(body) != "rout "+Version+"\n" {
				t.Fatalf("version alias: %v %v %q", err, e, body)
			}
		})
	}
	got, e := os.ReadFile(settings)
	if e != nil || string(got) != string(invalid) {
		t.Fatal("version changed existing settings")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "settings.json" {
		t.Fatal("version created runtime files")
	}
}

func TestVersionFlagsRespectTerminatorAndFlagValues(t *testing.T) {
	flags, rest := splitFlags([]string{"--home", "--version", "export", "--", "-v"})
	if !reflect.DeepEqual(flags, []string{"--home", "--version"}) || !reflect.DeepEqual(rest, []string{"export", "-v"}) {
		t.Fatal("version flag consumed a flag value or an argument after --", flags, rest)
	}
}
