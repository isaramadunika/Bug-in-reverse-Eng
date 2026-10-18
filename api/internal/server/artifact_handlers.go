package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/storage"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	// Verify project exists in org
	if _, err := s.store.GetProject(r.Context(), orgID, projectID); err != nil {
		if errors.Is(err, store.ErrProjectNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	// 32MB max memory buffer, remainder streams to disk
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return httpx.BadRequest("Failed to parse multipart upload: " + err.Error())
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		return httpx.BadRequest("Missing required 'file' form field")
	}
	defer file.Close()

	originalFilename := header.Filename
	if originalFilename == "" {
		originalFilename = "application.apk"
	}
	// Sanitize filename display
	originalFilename = filepath.Base(originalFilename)

	// Stream to quarantine temp file while computing sha256
	tempFile, err := os.CreateTemp("", "rb-upload-*.apk")
	if err != nil {
		return fmt.Errorf("create quarantine file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}()

	hasher := sha256.New()
	limitReader := io.LimitReader(file, s.cfg.MaxUploadBytes+1)
	writer := io.MultiWriter(tempFile, hasher)

	copied, err := io.Copy(writer, limitReader)
	if err != nil {
		return fmt.Errorf("stream upload: %w", err)
	}
	if copied > s.cfg.MaxUploadBytes {
		return httpx.Error(http.StatusRequestEntityTooLarge, fmt.Sprintf("APK file exceeds maximum permitted size of %d MB", s.cfg.MaxUploadBytes/(1024*1024)))
	}

	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	// Validate APK structure, zip bombs, and path traversal
	meta, err := storage.ValidateAndInspectAPK(tempFile, copied)
	if err != nil {
		return httpx.BadRequest("APK validation failed: " + err.Error())
	}

	// Seek tempFile back to 0 to copy into permanent storage
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek temp file: %w", err)
	}

	storageKey := fmt.Sprintf("artifacts/%s/%s.apk", orgID, sha256Hex)
	if _, err := s.storage.Put(r.Context(), storageKey, tempFile); err != nil {
		return fmt.Errorf("persist artifact: %w", err)
	}

	// Insert into DB
	art, err := s.store.CreateOrGetArtifact(r.Context(), orgID, sha256Hex, copied, storageKey)
	if err != nil {
		return fmt.Errorf("record artifact: %w", err)
	}

	var pkgPtr, verNamePtr *string
	if meta.PackageName != "" {
		pkgPtr = &meta.PackageName
	}
	if meta.VersionName != "" {
		verNamePtr = &meta.VersionName
	}
	var verCodePtr *int64
	if meta.VersionCode > 0 {
		verCodePtr = &meta.VersionCode
	}
	var minSDKPtr, targetSDKPtr *int
	if meta.MinSDK > 0 {
		minSDKPtr = &meta.MinSDK
	}
	if meta.TargetSDK > 0 {
		targetSDKPtr = &meta.TargetSDK
	}

	av, err := s.store.CreateArtifactVersion(r.Context(), projectID, art.ID, &store.CreateArtifactVersionInput{
		OriginalFilename: originalFilename,
		Source:           "upload",
		PackageName:      pkgPtr,
		VersionName:      verNamePtr,
		VersionCode:      verCodePtr,
		MinSDK:           minSDKPtr,
		TargetSDK:        targetSDKPtr,
		Permissions:      meta.Permissions,
		UploadedBy:       u.ID,
	})
	if err != nil {
		return fmt.Errorf("record artifact version: %w", err)
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "artifact.uploaded",
		TargetType:  "artifact_version",
		TargetID:    av.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"sha256":            sha256Hex,
			"size_bytes":        copied,
			"original_filename": originalFilename,
			"project_id":        projectID,
			"package_name":      meta.PackageName,
		},
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"artifact_version": av,
		"sha256":           sha256Hex,
		"size_bytes":       copied,
	})
	return nil
}

type importURLReq struct {
	URL string `json:"url"`
}

func (s *Server) importArtifactURL(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	if _, err := s.store.GetProject(r.Context(), orgID, projectID); err != nil {
		if errors.Is(err, store.ErrProjectNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	var req importURLReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	req.URL = strings.TrimSpace(req.URL)

	parsedURL, err := httpx.ValidatePublicURL(req.URL, s.cfg.IsDev())
	if err != nil {
		return httpx.BadRequest("Invalid URL: " + err.Error())
	}

	// Use SSRF-hardened client with pinned DNS dialer
	client := httpx.NewSSRFSafeClient(45*time.Second, s.cfg.IsDev())

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create import request: %w", err)
	}
	httpReq.Header.Set("User-Agent", "ReverseBug-Importer/1.0 (+https://reversebug.io)")

	resp, err := client.Do(httpReq)
	if err != nil {
		return httpx.BadRequest("Failed to fetch target URL: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return httpx.BadRequest(fmt.Sprintf("Remote server returned HTTP status %d", resp.StatusCode))
	}

	if resp.ContentLength > s.cfg.MaxUploadBytes {
		return httpx.Error(http.StatusRequestEntityTooLarge, fmt.Sprintf("Remote APK exceeds maximum size of %d MB", s.cfg.MaxUploadBytes/(1024*1024)))
	}

	// Determine original filename from URL path
	filename := filepath.Base(parsedURL.Path)
	if filename == "" || filename == "/" || filename == "." {
		filename = "downloaded.apk"
	}

	// Stream to quarantine temp file
	tempFile, err := os.CreateTemp("", "rb-import-*.apk")
	if err != nil {
		return fmt.Errorf("create quarantine file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}()

	hasher := sha256.New()
	limitReader := io.LimitReader(resp.Body, s.cfg.MaxUploadBytes+1)
	writer := io.MultiWriter(tempFile, hasher)

	copied, err := io.Copy(writer, limitReader)
	if err != nil {
		return fmt.Errorf("stream download: %w", err)
	}
	if copied > s.cfg.MaxUploadBytes {
		return httpx.Error(http.StatusRequestEntityTooLarge, "Downloaded APK exceeds maximum permitted size")
	}

	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	// Validate APK
	meta, err := storage.ValidateAndInspectAPK(tempFile, copied)
	if err != nil {
		return httpx.BadRequest("Downloaded file is not a valid APK: " + err.Error())
	}

	// Rewind and persist
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek temp file: %w", err)
	}

	storageKey := fmt.Sprintf("artifacts/%s/%s.apk", orgID, sha256Hex)
	if _, err := s.storage.Put(r.Context(), storageKey, tempFile); err != nil {
		return fmt.Errorf("persist artifact: %w", err)
	}

	art, err := s.store.CreateOrGetArtifact(r.Context(), orgID, sha256Hex, copied, storageKey)
	if err != nil {
		return fmt.Errorf("record artifact: %w", err)
	}

	var pkgPtr, verNamePtr *string
	if meta.PackageName != "" {
		pkgPtr = &meta.PackageName
	}
	if meta.VersionName != "" {
		verNamePtr = &meta.VersionName
	}
	var verCodePtr *int64
	if meta.VersionCode > 0 {
		verCodePtr = &meta.VersionCode
	}
	var minSDKPtr, targetSDKPtr *int
	if meta.MinSDK > 0 {
		minSDKPtr = &meta.MinSDK
	}
	if meta.TargetSDK > 0 {
		targetSDKPtr = &meta.TargetSDK
	}

	sourceURL := parsedURL.String()
	av, err := s.store.CreateArtifactVersion(r.Context(), projectID, art.ID, &store.CreateArtifactVersionInput{
		OriginalFilename: filename,
		Source:           "url_import",
		SourceURL:        &sourceURL,
		PackageName:      pkgPtr,
		VersionName:      verNamePtr,
		VersionCode:      verCodePtr,
		MinSDK:           minSDKPtr,
		TargetSDK:        targetSDKPtr,
		Permissions:      meta.Permissions,
		UploadedBy:       u.ID,
	})
	if err != nil {
		return fmt.Errorf("record artifact version: %w", err)
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "artifact.imported",
		TargetType:  "artifact_version",
		TargetID:    av.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"sha256":     sha256Hex,
			"source_url": sourceURL,
			"project_id": projectID,
		},
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"artifact_version": av,
		"sha256":           sha256Hex,
		"size_bytes":       copied,
	})
	return nil
}

func (s *Server) listArtifactVersions(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	versions, err := s.store.ListArtifactVersions(r.Context(), orgID, projectID)
	if err != nil {
		return err
	}
	if versions == nil {
		versions = []store.ArtifactVersion{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"artifacts": versions})
	return nil
}

func (s *Server) getArtifactVersion(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	versionID := chi.URLParam(r, "versionID")

	av, err := s.store.GetArtifactVersion(r.Context(), orgID, versionID)
	if errors.Is(err, store.ErrArtifactNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"artifact": av})
	return nil
}
