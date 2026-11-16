package main

/*

	Checks security issues in project dependencies. Without arguments, it looks
	for a "composer.lock" file in the current directory. Pass it explicitly to check
	a specific "composer.lock" file.

*/

import (
	"flag"
	"fmt"
	"os"

	"github.com/fabpot/local-php-security-checker/v2/security"
)

var (
	version = "dev"
	date    = "unknown"
)

const (
	exitOK                   = 0
	exitVulnerabilitiesFound = 1
	exitInvalidFlag          = 2
	exitFailure              = 127
)

func main() {
	format := flag.String("format", "ansi", "Output format (ansi, text, junit, markdown, json, or yaml)")
	path := flag.String("path", "", "composer.lock file or directory")
	advisoryArchiveURL := flag.String("archive", security.AdvisoryArchiveURL, "Advisory archive URL")
	cacheDir := flag.String("cache-dir", os.TempDir(), "Cache directory")
	local := flag.Bool("local", false, "Do not make HTTP calls (needs a valid cache file)")
	noDevPackages := flag.Bool("no-dev", false, "Do not check packages listed under require-dev")
	updateCacheOnly := flag.Bool("update-cache", false, "Update the cache (other flags are ignored)")
	disableExitCode := flag.Bool("disable-exit-code", false, "Whether to fail when issues are detected")
	help := flag.Bool("help", false, "Output help and version")
	versionFlag := flag.Bool("version", false, "Output version")
	flag.Parse()

	if *help {
		fmt.Printf("Local PHP Security Checker %s, built at %s\n\n", version, date)
		flag.Usage()
		os.Exit(exitOK)
	}

	if *versionFlag {
		fmt.Printf("Local PHP Security Checker %s, built at %s\n", version, date)
		os.Exit(exitOK)
	}

	db, err := security.NewDB(*local, *advisoryArchiveURL, *cacheDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load the advisory DB: %s\n", err)
		os.Exit(exitFailure)
	}

	if *updateCacheOnly {
		return
	}

	if *format != "" && *format != "markdown" && *format != "json" && *format != "text" && *format != "yaml" && *format != "ansi" && *format != "junit" {
		fmt.Fprintf(os.Stderr, "format \"%s\" is not supported (supported formats: markdown, ansi, json, junit, and yaml)\n", *format)
		os.Exit(exitInvalidFlag)
	}

	lockReader, err := security.LocateLock(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitFailure)
	}

	lock, err := security.NewLock(lockReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load the lock file: %s\n", err)
		os.Exit(exitFailure)
	}

	// all formatters and the exit code must consume the same normalized result
	vulns := security.Normalize(security.Analyze(lock, db, *noDevPackages))

	output, err := security.Format(vulns, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to output the results: %s\n", err)
		os.Exit(exitFailure)
	}
	fmt.Print(string(output))

	if os.Getenv("GITHUB_WORKSPACE") != "" {
		gOutFile := os.Getenv("GITHUB_OUTPUT")

		f, err := os.OpenFile(gOutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to open github output: %s\n", err)
			os.Exit(exitFailure)
		}
		defer f.Close()

		// inside a Github action, export vulns
		rawOutput, err := security.Format(vulns, "raw_json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to output the results: %s\n", err)
			os.Exit(exitFailure)
		}
		if _, err = f.WriteString("vulns=" + string(rawOutput) + "\n"); err != nil {
			fmt.Fprintf(os.Stderr, "unable to write into github output: %s\n", err)
			os.Exit(exitFailure)
		}
	}

	if vulns.Count() > 0 && !*disableExitCode {
		os.Exit(exitVulnerabilitiesFound)
	}
}
