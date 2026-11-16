package security

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validLockContents = `{
    "packages": [{"name": "symfony/apache-pack", "version": "v1.0.1"}],
    "packages-dev": []
}`

const validComposerJSONContents = `{
    "name": "fabpot/_temp",
    "require": {"symfony/apache-pack": "^1.0"}
}`

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0644))
}

func createProject(t *testing.T, dir string) string {
	t.Helper()
	root := filepath.Join(dir, "project")
	require.NoError(t, os.MkdirAll(root, 0755))
	writeFile(t, filepath.Join(root, "composer.json"), validComposerJSONContents)
	writeFile(t, filepath.Join(root, "composer.lock"), validLockContents)
	return root
}

func TestLocateLockNormalLayouts(t *testing.T) {
	root := createProject(t, t.TempDir())

	for _, path := range []string{
		root,
		filepath.Join(root, "composer.json"),
		filepath.Join(root, "composer.lock"),
	} {
		reader, err := LocateLock(path)
		assert.Nil(t, err, path)
		if reader != nil {
			if closer, ok := reader.(io.Closer); ok {
				closer.Close()
			}
		}
	}

	subdir := filepath.Join(root, "sub", "dir")
	require.NoError(t, os.MkdirAll(subdir, 0755))
	// The lock does not exist there, but a sibling lock resolved through
	// traversal must still be constrained to the same project root.
	traversalLock := filepath.Join(subdir, "..", "..", "composer.lock")
	project, err := locateProject(traversalLock)
	require.Nil(t, err)
	assert.Equal(t, filepath.Clean(root), project.root)
	assert.Equal(t, filepath.Join(root, "composer.lock"), project.lockPath)
}

func TestLocateLockFindsRootUpwards(t *testing.T) {
	root := createProject(t, t.TempDir())
	nested := filepath.Join(root, "nested", "package")
	require.NoError(t, os.MkdirAll(nested, 0755))
	lockPath := filepath.Join(nested, "composer.lock")
	writeFile(t, lockPath, validLockContents)

	project, err := locateProject(lockPath)
	require.Nil(t, err)
	assert.Equal(t, filepath.Clean(root), project.root)
	assert.Equal(t, lockPath, project.lockPath)
}

func TestLocateLockRejectsSymlinkEscapingRoot(t *testing.T) {
	workspace := t.TempDir()
	root := createProject(t, workspace)

	outside := filepath.Join(workspace, "outside")
	require.NoError(t, os.MkdirAll(outside, 0755))
	writeFile(t, filepath.Join(outside, "composer.lock"), validLockContents)

	escapingLock := filepath.Join(root, "composer.lock")
	require.NoError(t, os.Remove(escapingLock))
	require.NoError(t, os.Symlink(filepath.Join("..", "outside", "composer.lock"), escapingLock))

	_, err := locateProject(escapingLock)
	assert.Error(t, err)
	_, err = LocateLock(root)
	assert.Error(t, err)
}

func TestLocateLockRejectsEscapingComposerJSON(t *testing.T) {
	workspace := t.TempDir()
	root := createProject(t, workspace)

	outside := filepath.Join(workspace, "outside")
	require.NoError(t, os.MkdirAll(outside, 0755))
	writeFile(t, filepath.Join(outside, "composer.json"), validComposerJSONContents)

	escapingJSON := filepath.Join(root, "composer.json")
	require.NoError(t, os.Remove(escapingJSON))
	require.NoError(t, os.Symlink(filepath.Join("..", "outside", "composer.json"), escapingJSON))

	_, err := locateProject(escapingJSON)
	assert.Error(t, err)
}

func TestLocateLockRejectsVendorLock(t *testing.T) {
	root := createProject(t, t.TempDir())

	vendorLock := filepath.Join(root, "vendor", "some-vendor", "some-package", "composer.lock")
	writeFile(t, vendorLock, validLockContents)

	// A lock physically located in a vendor directory, even though the
	// upward search finds the project's own composer.json.
	_, err := locateProject(vendorLock)
	assert.Error(t, err)

	// A root-level lock name that is a symbolic link to a same-named file
	// inside vendor must not be audited as the project lock.
	linkedLock := filepath.Join(root, "linked-composer.lock")
	require.NoError(t, os.Symlink(vendorLock, linkedLock))
	_, err = locateProject(linkedLock)
	assert.Error(t, err)
}

func TestLocateLockAcceptsSymlinkedProjectRoot(t *testing.T) {
	workspace := t.TempDir()
	root := createProject(t, workspace)
	link := filepath.Join(workspace, "project-link")
	require.NoError(t, os.Symlink(root, link))

	project, err := locateProject(link)
	require.Nil(t, err)
	assert.Equal(t, filepath.Clean(root), project.root)
	assert.Equal(t, filepath.Join(root, "composer.lock"), project.lockPath)
}

func TestLocateLockRejectsAmbiguousInput(t *testing.T) {
	root := createProject(t, t.TempDir())

	_, err := locateProject(filepath.Join(root, "missing", "composer.lock"))
	assert.Error(t, err)

	directoryAsLock := filepath.Join(root, "weird.lock")
	require.NoError(t, os.MkdirAll(directoryAsLock, 0755))
	_, err = locateProject(directoryAsLock)
	assert.Error(t, err)
}

func TestResolveCachePathMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := resolveCachePath(missing)
	assert.Error(t, err)
}

func TestResolveCachePathRejectsEscapingSymlink(t *testing.T) {
	workspace := t.TempDir()
	cacheDir := filepath.Join(workspace, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	outside := filepath.Join(workspace, "outside-cache.json")
	writeFile(t, outside, "{}")
	require.NoError(t, os.Symlink(outside, filepath.Join(cacheDir, cacheFileName)))

	_, err := resolveCachePath(cacheDir)
	assert.Error(t, err)
}

func TestNewDBLocalWithoutCacheFails(t *testing.T) {
	_, err := NewDB(true, "", t.TempDir())
	assert.Equal(t, "unable to fetch advisories: --local can only be used when a local HTTP cache is available", err.Error())
}

func TestNewDBLocalWithValidCache(t *testing.T) {
	cacheDir := t.TempDir()
	writeValidCache(t, cacheDir)

	db, err := NewDB(true, "", cacheDir)
	require.Nil(t, err)
	assert.Equal(t, 1, len(db.Advisories))
	assert.Equal(t, "Test advisory", db.Advisories[0].Title)
}

func TestWriteCacheRejectsSymlink(t *testing.T) {
	workspace := t.TempDir()
	cacheDir := filepath.Join(workspace, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	outside := filepath.Join(workspace, "outside-cache.json")
	writeFile(t, outside, "{}")
	cachePath := filepath.Join(cacheDir, cacheFileName)
	require.NoError(t, os.Symlink(outside, cachePath))

	db := &AdvisoryDB{cachePath: cachePath}
	assert.Error(t, db.writeCache([]byte("{}")))
}

func writeValidCache(t *testing.T, cacheDir string) {
	t.Helper()

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("advisory.yaml")
	require.Nil(t, err)
	_, err = entry.Write([]byte("title: Test advisory\nlink: https://example.com\n"))
	require.Nil(t, err)
	require.Nil(t, writer.Close())

	cache := &Cache{Body: archive.Bytes()}
	contents, err := json.Marshal(cache)
	require.Nil(t, err)
	writeFile(t, filepath.Join(cacheDir, cacheFileName), string(contents))
}
