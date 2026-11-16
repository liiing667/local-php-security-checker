package security

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AdvisoryArchiveURL represents the advisories database URL
const AdvisoryArchiveURL = "https://codeload.github.com/FriendsOfPHP/security-advisories/zip/master"

// AdvisoryDB stores all known security advisories
type AdvisoryDB struct {
	Advisories  []Advisory
	cachePath   string
	noHTTPCalls bool
}

// Advisory represents a single security advisory
type Advisory struct {
	Title     string             `yaml:"title"`
	Link      string             `yaml:"link"`
	CVE       string             `yaml:"cve"`
	Branches  map[string]*Branch `yaml:"branches"`
	Reference string             `yaml:"reference"`
}

// Branch represents a Git branch
type Branch struct {
	Versions []string `yaml:"versions"`
	Time     Time     `yaml:"time"`
}

// Cache stores the Github response to save bandwith
type Cache struct {
	Key  string
	Date string
	Body []byte
}

// NewDB fetches the advisory DB from Github
func NewDB(noHTTPCalls bool, advisoryArchiveURL, cacheDir string) (*AdvisoryDB, error) {
	cachePath, err := resolveCachePath(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("unable to use the advisory cache: %s", err)
	}
	db := &AdvisoryDB{noHTTPCalls: noHTTPCalls, cachePath: cachePath}
	if err := db.load(advisoryArchiveURL); err != nil {
		return nil, fmt.Errorf("unable to fetch advisories: %s", err)
	}

	return db, nil
}

// load loads fetches the database from Github and reads/loads current advisories
// from the repository. Cache handling is delegated to http.Transport and
// **must** be handled appropriately.
func (db *AdvisoryDB) load(advisoryArchiveURL string) error {
	if len(db.Advisories) > 0 {
		return nil
	}

	db.Advisories = []Advisory{}

	var cache *Cache
	if cacheContent, err := os.ReadFile(db.cachePath); err == nil {
		// ignore errors
		json.Unmarshal(cacheContent, &cache)
	}

	if db.noHTTPCalls && cache == nil {
		return errors.New("--local can only be used when a local HTTP cache is available")
	}

	if !db.noHTTPCalls {
		req, err := http.NewRequest("GET", advisoryArchiveURL, nil)
		if err != nil {
			return err
		}
		if cache != nil {
			req.Header.Add("If-None-Match", cache.Key)
			req.Header.Add("If-Modified-Since", cache.Date)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body []byte
		if resp.StatusCode != http.StatusNotModified {
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			key := resp.Header.Get("ETag")
			date := resp.Header.Get("Date")
			if key != "" || date != "" {
				cache = &Cache{Key: key, Date: date, Body: body}
			}
			cacheContent, err := json.Marshal(cache)
			if err == nil {
				if err := db.writeCache(cacheContent); err != nil {
					return err
				}
			}
		}
	}

	zipReader, err := zip.NewReader(bytes.NewReader(cache.Body), int64(len(cache.Body)))
	if err != nil {
		return err
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".yaml") {
			continue
		}
		f, err := zipFile.Open()
		if err != nil {
			return err
		}
		defer f.Close()

		contents, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("unable to read %s: %s", zipFile.Name, err)
		}

		var pa Advisory
		if err := yaml.Unmarshal(contents, &pa); err != nil {
			return fmt.Errorf("%s is not a valid YAML file: %s", zipFile.Name, err)
		}

		db.Advisories = append(db.Advisories, pa)
	}

	return nil
}

// writeCache stores the advisory archive while making sure the cache file
// cannot be redirected outside of the verified cache directory through a
// symbolic link.
func (db *AdvisoryDB) writeCache(contents []byte) error {
	if info, err := os.Lstat(db.cachePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("advisory cache %s is a symbolic link", db.cachePath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("advisory cache %s is not a regular file", db.cachePath)
		}
	}
	return os.WriteFile(db.cachePath, contents, 0644)
}
