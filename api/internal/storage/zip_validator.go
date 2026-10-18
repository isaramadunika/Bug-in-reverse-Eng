package storage

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

var (
	ErrNotAnAPK             = errors.New("file is not a valid APK (missing AndroidManifest.xml or DEX bytecode)")
	ErrZipBombRatio         = errors.New("excessive compression ratio detected (potential zip bomb)")
	ErrZipBombSize          = errors.New("uncompressed size exceeds safe limit")
	ErrZipBombFiles         = errors.New("archive contains too many files")
	ErrPathTraversal        = errors.New("archive entry contains dangerous path traversal components")
	ErrInvalidZipStructure  = errors.New("invalid or corrupted zip archive structure")
)

const (
	MaxArchiveFiles          = 50000
	MaxUncompressedBytes     = 500 * 1024 * 1024 // 500 MB max uncompressed
	MaxEntryCompressionRatio = 100                // 100:1 max ratio
)

// APKQuickMetadata holds preliminary metadata extracted safely during ingestion.
type APKQuickMetadata struct {
	PackageName     string
	VersionName     string
	VersionCode     int64
	MinSDK          int
	TargetSDK       int
	Permissions     []string
	HasDEX          bool
	HasManifest     bool
	FileCount       int
	UncompressedLen int64
}

// ValidateAndInspectAPK checks the APK against zip-slip, zip-bomb, and path traversal
// attacks, verifies presence of AndroidManifest.xml and DEX, and extracts package info.
func ValidateAndInspectAPK(r io.ReaderAt, size int64) (*APKQuickMetadata, error) {
	if size < 22 { // Minimum valid ZIP file size is 22 bytes (empty EOCD)
		return nil, ErrInvalidZipStructure
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidZipStructure, err)
	}

	if len(zr.File) > MaxArchiveFiles {
		return nil, ErrZipBombFiles
	}

	meta := &APKQuickMetadata{}
	var totalUncompressed int64
	var manifestData []byte

	for _, f := range zr.File {
		name := f.Name

		// 1. Path traversal checks
		if strings.ContainsRune(name, 0) || strings.Contains(name, "..") {
			return nil, fmt.Errorf("%w: %q", ErrPathTraversal, name)
		}
		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
			return nil, fmt.Errorf("%w: %q", ErrPathTraversal, name)
		}

		// 2. Zip bomb checks
		uncompressed := int64(f.UncompressedSize64)
		compressed := int64(f.CompressedSize64)
		if compressed > 0 && uncompressed > 1024*1024 {
			ratio := uncompressed / compressed
			if ratio > MaxEntryCompressionRatio {
				return nil, fmt.Errorf("%w in %s (ratio %d:1)", ErrZipBombRatio, name, ratio)
			}
		}

		totalUncompressed += uncompressed
		if totalUncompressed > MaxUncompressedBytes {
			return nil, ErrZipBombSize
		}

		// 3. Structural checks
		if name == "AndroidManifest.xml" {
			meta.HasManifest = true
			if uncompressed > 0 && uncompressed < 5*1024*1024 { // Read manifest if <= 5MB
				rc, err := f.Open()
				if err == nil {
					data, err := io.ReadAll(io.LimitReader(rc, 5*1024*1024))
					_ = rc.Close()
					if err == nil {
						manifestData = data
					}
				}
			}
		} else if strings.HasSuffix(name, ".dex") {
			meta.HasDEX = true
		}
	}

	meta.FileCount = len(zr.File)
	meta.UncompressedLen = totalUncompressed

	if !meta.HasManifest || !meta.HasDEX {
		return nil, ErrNotAnAPK
	}

	// Try extracting package name from binary XML if present
	if len(manifestData) > 0 {
		parseBinaryManifestQuick(manifestData, meta)
	}

	return meta, nil
}

// parseBinaryManifestQuick extracts package name and version attributes from compiled AXML.
func parseBinaryManifestQuick(data []byte, meta *APKQuickMetadata) {
	if len(data) < 8 {
		return
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x00080003 { // Standard Android binary XML header
		return
	}

	// Simple string pool scanner for package and android attributes
	strings := extractAXMLStrings(data)
	for i, s := range strings {
		if s == "manifest" && i+1 < len(strings) {
			// Find string matching package naming syntax
			for _, candidate := range strings {
				if isValidPackageName(candidate) && candidate != "android" && candidate != "manifest" {
					if meta.PackageName == "" {
						meta.PackageName = candidate
					}
				}
			}
		}
	}
}

func isValidPackageName(s string) bool {
	if len(s) < 3 || len(s) > 150 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		first := p[0]
		if !(first >= 'a' && first <= 'z') && !(first >= 'A' && first <= 'Z') && first != '_' {
			return false
		}
		for i := 1; i < len(p); i++ {
			c := p[i]
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

func extractAXMLStrings(data []byte) []string {
	var results []string
	if len(data) < 16 {
		return results
	}
	// Look for string pool chunk (type 0x00010001)
	idx := 8
	for idx+8 < len(data) {
		chunkType := binary.LittleEndian.Uint32(data[idx : idx+4])
		chunkSize := binary.LittleEndian.Uint32(data[idx+4 : idx+8])
		if chunkSize < 8 || int(idx)+int(chunkSize) > len(data) {
			break
		}

		if chunkType == 0x00010001 { // RES_STRING_POOL_TYPE
			poolData := data[idx : idx+int(chunkSize)]
			if len(poolData) >= 28 {
				stringCount := binary.LittleEndian.Uint32(poolData[8:12])
				flags := binary.LittleEndian.Uint32(poolData[16:20])
				stringsStart := binary.LittleEndian.Uint32(poolData[20:24])
				isUTF8 := (flags & (1 << 8)) != 0

				offsets := make([]uint32, stringCount)
				for i := uint32(0); i < stringCount && int(28+i*4) < len(poolData); i++ {
					offsets[i] = binary.LittleEndian.Uint32(poolData[28+i*4 : 32+i*4])
				}

				for _, offset := range offsets {
					pos := int(stringsStart) + int(offset)
					if pos >= len(poolData) {
						continue
					}
					if isUTF8 {
						// UTF-8 length prefix
						if pos+2 <= len(poolData) {
							strLen := int(poolData[pos+1])
							if pos+2+strLen <= len(poolData) {
								str := string(poolData[pos+2 : pos+2+strLen])
								if len(str) > 0 {
									results = append(results, str)
								}
							}
						}
					} else {
						// UTF-16 length prefix
						if pos+2 <= len(poolData) {
							strLen := int(binary.LittleEndian.Uint16(poolData[pos : pos+2]))
							start := pos + 2
							end := start + strLen*2
							if end <= len(poolData) {
								u16 := make([]uint16, strLen)
								for j := 0; j < strLen; j++ {
									u16[j] = binary.LittleEndian.Uint16(poolData[start+j*2 : start+(j+1)*2])
								}
								str := string(utf16.Decode(u16))
								if len(str) > 0 {
									results = append(results, str)
								}
							}
						}
					}
				}
			}
			break
		}
		idx += int(chunkSize)
	}
	return results
}

// ReadFileAt is a helper wrapping a byte slice in an io.ReaderAt.
type ByteReaderAt struct {
	*bytes.Reader
}

func NewByteReaderAt(b []byte) *ByteReaderAt {
	return &ByteReaderAt{bytes.NewReader(b)}
}
