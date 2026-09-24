package api

// Version-matched downloads served by the appliance itself. The Windows
// bundle is a CI-built asset on the GitHub release for the running version;
// the core fetches it once and keeps it under <state>/downloads so the
// console always offers the bundle that matches the console you are using,
// and keeps offering it if the release host is unreachable later.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rostor.org/app/internal/audit"
)

const windowsBundle = "rostor-windows-amd64.zip"

type downloadStatus struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Cached    bool       `json:"cached"`
	Size      int64      `json:"size,omitempty"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

var downloadMu sync.Mutex

func (s *Server) downloadPath(name string) string {
	return filepath.Join(s.StateDir, "downloads", s.Version, name)
}

// ensureBundle returns the local path of the bundle for the running version,
// fetching it from the release if needed. "dev" builds have no release.
func (s *Server) ensureBundle(ctx context.Context, name string) (string, error) {
	path := s.downloadPath(name)
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return path, nil
	}
	if !strings.HasPrefix(s.Version, "v") {
		return "", fmt.Errorf("no release for a development build (%s)", s.Version)
	}
	downloadMu.Lock()
	defer downloadMu.Unlock()
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return path, nil
	}
	repo := s.ReleaseRepo
	if repo == "" {
		repo = "rostor-org/app"
	}
	// Resolve the asset through the GitHub API so it works for private and
	// public repositories alike (browser_download_url does not).
	api := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, s.Version)
	req, _ := http.NewRequestWithContext(ctx, "GET", api, nil)
	if s.ReleaseToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.ReleaseToken)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("release %s: %s", s.Version, resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	var url string
	for _, a := range rel.Assets {
		if a.Name == name {
			url = a.URL
		}
	}
	if url == "" {
		return "", fmt.Errorf("release %s has no %s", s.Version, name)
	}
	req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/octet-stream")
	if s.ReleaseToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.ReleaseToken)
	}
	resp2, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		return "", fmt.Errorf("download %s: %s", name, resp2.Status)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), name+".*.part")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, resp2.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return path, os.Rename(tmp.Name(), path)
}

func (s *Server) handleDownloadStatus(w http.ResponseWriter, r *http.Request) {
	st := downloadStatus{Name: windowsBundle, Version: s.Version}
	if fi, err := os.Stat(s.downloadPath(windowsBundle)); err == nil {
		st.Cached, st.Size = true, fi.Size()
		m := fi.ModTime()
		st.FetchedAt = &m
	}
	s.writeJSON(w, 200, map[string]any{"windows": st})
}

// handleDownloadWindows streams the bundle, fetching it first if needed.
func (s *Server) handleDownloadWindows(w http.ResponseWriter, r *http.Request) {
	path, err := s.ensureBundle(r.Context(), windowsBundle)
	if err != nil {
		s.writeErr(w, r, 502, "download.unavailable", map[string]any{"detail": err.Error()})
		return
	}
	a := actorOf(r)
	s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "download.windows_bundle", TargetType: "release", TargetID: s.Version,
		Outcome: "ok", CorrelationID: corrOf(r)})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rostor-windows-%s.zip"`, s.Version))
	http.ServeFile(w, r, path)
}

// PrefetchDownloads warms the cache in the background after start (an
// update just happened, or the box just booted).
func (s *Server) PrefetchDownloads(ctx context.Context) {
	if _, err := s.ensureBundle(ctx, windowsBundle); err != nil {
		s.Log.Info("windows bundle not prefetched", "err", err)
	}
}
