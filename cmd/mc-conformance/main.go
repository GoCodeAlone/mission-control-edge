package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/GoCodeAlone/mission-control-edge/conformance"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mc-conformance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var providerValue string
	var jsonPath string
	var junitPath string
	var timeout time.Duration
	flags.StringVar(&providerValue, "provider", "", "external provider command")
	flags.StringVar(&jsonPath, "json", "-", "JSON report path or - for stdout")
	flags.StringVar(&junitPath, "junit", "", "optional JUnit report path")
	flags.DurationVar(&timeout, "timeout", 15*time.Second, "per-case timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "mc_conformance_invalid_arguments")
		return 2
	}
	command, err := splitCommand(providerValue)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mc_conformance_invalid_provider_command")
		return 2
	}
	report, err := conformance.Run(context.Background(), conformance.RunnerConfig{
		ProviderCommand: command,
		CaseTimeout:     timeout,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mc_conformance_failed")
		return 2
	}
	if err := writeReport(jsonPath, stdout, func(writer io.Writer) error {
		return conformance.WriteJSON(writer, report)
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, "mc_conformance_report_failed")
		return 2
	}
	if junitPath != "" {
		if err := writeReport(junitPath, stdout, func(writer io.Writer) error {
			return conformance.WriteJUnit(writer, report)
		}); err != nil {
			_, _ = fmt.Fprintln(stderr, "mc_conformance_report_failed")
			return 2
		}
	}
	if report.HasRequiredFailures() {
		return 1
	}
	return 0
}

func writeReport(path string, stdout io.Writer, write func(io.Writer) error) error {
	if path == "-" {
		return write(stdout)
	}
	if path == "" {
		return fmt.Errorf("report path is required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- the local caller explicitly selects the report destination.
	if err != nil {
		return err
	}
	writeErr := write(file)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func splitCommand(value string) ([]string, error) {
	var result []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() == 0 {
			return
		}
		result = append(result, current.String())
		current.Reset()
	}
	for _, character := range value {
		if escaped {
			current.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		current.WriteRune(character)
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("provider command quoting is invalid")
	}
	flush()
	if len(result) == 0 {
		return nil, fmt.Errorf("provider command is required")
	}
	return result, nil
}
