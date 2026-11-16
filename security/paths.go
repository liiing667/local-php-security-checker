package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

const (
	composerJSONFile = "composer.json"
	composerLockFile = "composer.lock"
	cacheFileName    = "php_sec_db.json"
	vendorDir        = "vendor"
)

// realPath resolves path to an absolute path with all symbolic links
// resolved. Every path-boundary check in the package must operate on paths
// returned by realPath so that all Composer files and the advisory cache
// share a single verified boundary.
func realPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return real, nil
}

// isWithin reports whether target is root itself or located inside root.
// Both arguments must be symlink-resolved absolute paths.
func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// checkWithin fails when target is not rooted at root, which catches both
// directory traversal and symbolic links pointing outside of the verified
// boundary.
func checkWithin(root, target string) error {
	if !isWithin(root, target) {
		return fmt.Errorf("%s is outside of the verified path boundary %s", target, root)
	}
	return nil
}

// crossesVendor reports whether the path from root to target goes through a
// Composer vendor directory, which only contains dependencies rather than
// the project's own Composer files.
func crossesVendor(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == vendorDir {
			return true
		}
	}
	return false
}

// resolveCachePath verifies that the advisory cache directory is a real
// directory and that an existing cache file cannot escape it through a
// symbolic link, reusing the same real-path boundary checks as the Composer
// project resolution.
func resolveCachePath(cacheDir string) (string, error) {
	expanded, err := homedir.Expand(cacheDir)
	if err != nil {
		return "", err
	}
	realDir, err := realPath(expanded)
	if err != nil {
		return "", fmt.Errorf("cache directory %s is not accessible: %s", cacheDir, err)
	}
	info, err := os.Stat(realDir)
	if err != nil {
		return "", fmt.Errorf("cache directory %s is not accessible: %s", cacheDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cache directory %s is not a directory", cacheDir)
	}

	cachePath := filepath.Join(realDir, cacheFileName)
	if _, err := os.Lstat(cachePath); err == nil {
		realCache, err := realPath(cachePath)
		if err != nil {
			return "", err
		}
		if err := checkWithin(realDir, realCache); err != nil {
			return "", fmt.Errorf("advisory cache %s escapes its cache directory: %s", cachePath, err)
		}
		target, err := os.Stat(cachePath)
		if err != nil {
			return "", err
		}
		if !target.Mode().IsRegular() {
			return "", fmt.Errorf("advisory cache %s is not a regular file", cachePath)
		}
	}

	return cachePath, nil
}
