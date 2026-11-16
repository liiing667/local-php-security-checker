package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mitchellh/go-homedir"
	"io"
	"os"
	"path/filepath"
)

// Package represents a Composer package
type Package struct {
	Name    string  `json:"name"`
	Version Version `json:"version"`
	Time    Time    `json:"time,omitempty"`
}

// Lock represents a Composer lock file
type Lock struct {
	Packages    []Package `json:"packages"`
	DevPackages []Package `json:"packages-dev"`
}

// NewLock creates a lock file wrapper
func NewLock(reader io.Reader) (*Lock, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("unable to read lock file")
	}
	var l *Lock
	if err = json.Unmarshal(contents, &l); err != nil {
		return nil, errors.New("lock file is not valid JSON (not a composer.lock file?)")
	}
	if l.Packages == nil && l.DevPackages == nil {
		return nil, errors.New("lock file is not valid (no packages and no dev packages)")
	}
	return l, nil
}

// project describes a Composer project through paths that have all been
// resolved to their real location on disk. Every component shares the same
// verified root boundary so that directory traversal and symbolic links
// cannot make the checker audit files belonging to another project.
type project struct {
	root         string
	lockPath     string
	composerJSON string
}

// LocateLock locates a composer.lock
func LocateLock(path string) (io.Reader, error) {
	project, err := locateProject(path)
	if err != nil {
		return nil, err
	}

	reader, err := os.Open(project.lockPath)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid lock file: %s", project.lockPath, err)
	}

	return reader, nil
}

// locateProject resolves the Composer project behind path and verifies that
// every component (project root, composer.json and composer.lock) stays
// within the same real-path boundary.
func locateProject(path string) (*project, error) {
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, err
	}

	var rootDir, lockPath, composerJSONPath string
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		rootDir = cwd
		lockPath = filepath.Join(cwd, composerLockFile)
		composerJSONPath = filepath.Join(cwd, composerJSONFile)
	} else {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid lock file: %s", path, err)
		}
		if info.IsDir() {
			rootDir = path
			lockPath = filepath.Join(path, composerLockFile)
			composerJSONPath = filepath.Join(path, composerJSONFile)
		} else {
			base := filepath.Base(path)
			switch base {
			case composerLockFile:
				lockPath = path
			case composerJSONFile:
				composerJSONPath = path
				lockPath = filepath.Join(filepath.Dir(path), composerLockFile)
			default:
				lockPath = path
			}
		}
	}

	realLock, err := realPath(lockPath)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid lock file: %s", lockPath, err)
	}
	lockInfo, err := os.Stat(realLock)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid lock file: %s", realLock, err)
	}
	if !lockInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a valid lock file: not a regular file", realLock)
	}

	realRoot, err := resolveProjectRoot(rootDir, lockPath, realLock)
	if err != nil {
		return nil, err
	}
	if err := checkWithin(realRoot, realLock); err != nil {
		return nil, fmt.Errorf("%s escapes the project root %s", realLock, realRoot)
	}
	if crossesVendor(realRoot, realLock) {
		return nil, fmt.Errorf("%s is inside a vendor directory and is not the project lock file", realLock)
	}

	if composerJSONPath == "" {
		candidate := filepath.Join(realRoot, composerJSONFile)
		if fileExists(candidate) {
			composerJSONPath = candidate
		}
	}
	if composerJSONPath != "" {
		realJSON, err := realPath(composerJSONPath)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid composer.json file: %s", composerJSONPath, err)
		}
		jsonInfo, err := os.Stat(realJSON)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid composer.json file: %s", realJSON, err)
		}
		if !jsonInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a valid composer.json file: not a regular file", realJSON)
		}
		if err := checkWithin(realRoot, realJSON); err != nil {
			return nil, fmt.Errorf("%s escapes the project root %s", realJSON, realRoot)
		}
		composerJSONPath = realJSON
	}

	return &project{root: realRoot, lockPath: realLock, composerJSON: composerJSONPath}, nil
}

// resolveProjectRoot finds the real project root for a lock path. When the
// caller provided a directory or a composer.json, that directory is the
// candidate root. For a bare lock path the root is discovered by walking up
// from the lexical location of the input path (before symlink resolution)
// until a composer.json is found; without one, the lock's own directory is
// used. Anchoring on the lexical location is what keeps the boundary fixed
// when the lock itself is a symbolic link pointing elsewhere. The chosen
// root is then resolved through realPath before any boundary check.
func resolveProjectRoot(rootDir, lexicalLockPath, realLock string) (string, error) {
	if rootDir != "" {
		realRoot, err := realPath(rootDir)
		if err != nil {
			return "", fmt.Errorf("project root %s is not accessible: %s", rootDir, err)
		}
		rootInfo, err := os.Stat(realRoot)
		if err != nil {
			return "", fmt.Errorf("project root %s is not accessible: %s", realRoot, err)
		}
		if !rootInfo.IsDir() {
			return "", fmt.Errorf("project root %s is not a directory", realRoot)
		}
		return realRoot, nil
	}

	dir := filepath.Dir(lexicalLockPath)
	for {
		if fileExists(filepath.Join(dir, composerJSONFile)) {
			return realPath(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return realPath(filepath.Dir(lexicalLockPath))
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
