package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateMaliciousZip tests the ZIP generation functionality
// Note: This test is currently disabled due to interface changes
func TestGenerateMaliciousZip(t *testing.T) {
	// Test basic ZIP generation with current interface
	outputFile := "testdata/test_basic.zip"
	payloads := []string{"../../evil.txt"}
	depth := 2

	// Setup test directory
	t.Cleanup(func() {
		os.RemoveAll("testdata")
	})
	os.MkdirAll("testdata", 0755)

	// Test the function with current signature
	err := generateMaliciousZip(outputFile, payloads, depth)
	assert.NoError(t, err)

	// Verify the ZIP file was created
	_, err = os.Stat(outputFile)
	assert.NoError(t, err)

	// Verify ZIP contents exist
	verifyZipContents(t, outputFile, []string{"../../evil.txt"}, "malicious content")
}

func TestIsVulnerableZip(t *testing.T) {
	tests := []struct {
		name          string
		createZip     func() string
		expectedVuln  bool
		expectedPaths []string
	}{
		{
			name: "vulnerable zip with path traversal",
			createZip: func() string {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f, _ := w.Create("../../evil.txt")
				f.Write([]byte("test"))
				w.Close()
				return createTempZip(t, buf.Bytes())
			},
			expectedVuln:  true,
			expectedPaths: []string{"../../evil.txt"},
		},
		{
			name: "safe zip",
			createZip: func() string {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f, _ := w.Create("safe/file.txt")
				f.Write([]byte("safe"))
				w.Close()
				return createTempZip(t, buf.Bytes())
			},
			expectedVuln:  false,
			expectedPaths: []string{},
		},
		{
			name: "multiple vulnerable files",
			createZip: func() string {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)

				f1, _ := w.Create("../../file1.txt")
				f1.Write([]byte("file1"))

				f2, _ := w.Create("normal.txt")
				f2.Write([]byte("normal"))

				f3, _ := w.Create("/etc/config")
				f3.Write([]byte("config"))

				w.Close()
				return createTempZip(t, buf.Bytes())
			},
			expectedVuln:  true,
			expectedPaths: []string{"../../file1.txt", "/etc/config"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zipPath := tt.createZip()
			t.Cleanup(func() {
				os.Remove(zipPath)
			})

			vulnerable, paths, err := isVulnerableZip(zipPath)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedVuln, vulnerable)

			if tt.expectedVuln {
				assert.ElementsMatch(t, tt.expectedPaths, paths)
			} else {
				assert.Empty(t, paths)
			}
		})
	}
}

// TestExtractZip is currently disabled due to missing extractZip function
// This test would verify ZIP extraction functionality
func TestExtractZip(t *testing.T) {
	t.Skip("TestExtractZip is disabled - extractZip function not implemented")

	// TODO: Implement extractZip function and enable this test
	// This test should verify:
	// 1. Safe ZIP extraction
	// 2. Detection of path traversal attempts during extraction
	// 3. Proper error handling for malicious ZIPs
}

func FuzzPathVulnerabilityDetection(f *testing.F) {
	// Comprehensive seed corpus covering all edge cases
	advancedTestCases := []string{
		// Parent directory traversal patterns
		"../etc/passwd", "../../windows/system32", "../../../root/.ssh",
		"00..", "..0", "a../b", "file..txt", "....",

		// URL encoding patterns
		"%2e%2e/etc/passwd", "%2e%2e%2fwindows", "~%0", "%0%",
		"%2f%2e%2e%2f", "%5c%2e%2e%5c", "file%00.txt",

		// Absolute path patterns
		"/etc/passwd", "/root/.ssh/id_rsa", "\\windows\\system32",
		"/", "\\", "//server/share", "\\\\server\\share",

		// Tilde expansion patterns
		"~/", "~/.ssh/config", "~..", "~%0", "~0", "~A/0",
		"~user/file", "~123", "~admin/.bashrc", "~root/",

		// Colon patterns (Windows drive letters and device paths)
		"C:\\", "A:\\windows", "0:\\", "00:\\", ":\\", ":\\0",
		":0", "A:A", "0:00", ":", "A:", "Z:file.txt",
		"1:2:3", "device:path", "COM1:", "LPT1:",

		// Windows device names
		"CON", "PRN", "AUX", "NUL", "COM1", "COM9",
		"LPT1", "LPT9", "con.txt", "prn.log",

		// Mixed and complex patterns
		"../~user/file", "~/../etc/passwd", "C:..\\windows",
		"%2e%2e/~/file", ":\\../etc", "0:\\%2e%2e",
		"CON/../file", "~%2e%2e/root", "A:~user/file",

		// Edge cases and special characters
		"", ".", "..", "...", "....", "file.txt",
		"normal/path/file.txt", "file\\with\\backslashes",
		"file/with/forward/slashes", "file with spaces",
		"file\x00null", "file\ttab", "file\nnewline",

		// Adversarial patterns designed to confuse parsers
		"..\\../etc", "../\\../windows", "..\\/etc",
		"~\\../root", "~/\\../etc", "C:\\../windows",
		":../etc", "0:../windows", "A:\\../system32",

		// Unicode and international characters
		"../файл.txt", "~/用户/文件", "C:\\ファイル",
		"../café/file", "~/naïve/path", "résumé.txt",
	}

	// Add all seed cases to fuzz corpus
	for _, tc := range advancedTestCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Test the path vulnerability detection directly
		actualResult := isVulnerablePath(path)

		// Use our advanced analyzer to determine expected result
		analyzer := NewPathAnalyzer(path)
		expectedResult := analyzer.IsVulnerable()

		// The results should match (consistency check)
		assert.Equal(t, expectedResult, actualResult,
			"Inconsistency detected for path: %q", path)

		// Additional validation: if detected as vulnerable, verify why
		if actualResult {
			validateVulnerabilityReason(t, path, analyzer)
		}

		// Test edge case: very long paths
		if len(path) > 1000 {
			// Should handle gracefully without panicking
			assert.NotPanics(t, func() {
				isVulnerablePath(path)
			}, "Should handle very long paths gracefully")
		}
	})
}

// FuzzGenerateAndScanZip performs end-to-end fuzz testing
func FuzzGenerateAndScanZip(f *testing.F) {
	// Seed with patterns that should definitely be caught
	vulnerablePatterns := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"/etc/shadow",
		"~/.ssh/id_rsa",
		"C:\\windows\\system32\\drivers\\etc\\hosts",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"CON",
		"00:\\",
	}

	for _, pattern := range vulnerablePatterns {
		f.Add(pattern)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Skip empty paths
		if path == "" {
			t.Skip()
		}

		tempDir, err := os.MkdirTemp("", "fuzz-*")
		require.NoError(t, err)
		t.Cleanup(func() {
			os.RemoveAll(tempDir)
		})

		// Create test ZIP with fuzzed path
		zipPath := filepath.Join(tempDir, "test.zip")
		err = generateMaliciousZip(zipPath, []string{path}, 3)
		if err != nil {
			t.Skip() // Skip paths that can't be created in ZIP
		}

		// Test vulnerability detection
		vulnerable, detectedPaths, err := isVulnerableZip(zipPath)
		require.NoError(t, err)

		// Cross-validate with direct path analysis
		directAnalysis := isVulnerablePath(path)

		// Results should be consistent
		assert.Equal(t, directAnalysis, vulnerable,
			"Inconsistent results for path %q: direct=%v, zip=%v, detected=%v",
			path, directAnalysis, vulnerable, detectedPaths)
	})
}

// validateVulnerabilityReason ensures that when a path is flagged as vulnerable,
// there's a clear reason why
func validateVulnerabilityReason(t *testing.T, path string, analyzer *PathVulnerabilityAnalyzer) {
	// Check each detection method to ensure at least one triggers
	hasParentTraversal := analyzer.detectParentDirectoryTraversal()
	hasURLEncoding := analyzer.detectURLEncoding()
	hasAbsolutePath := analyzer.detectAbsolutePaths()
	hasTildeExpansion := analyzer.detectTildeExpansion()
	hasColonPattern := analyzer.detectColonPatterns()
	hasDeviceName := analyzer.detectWindowsDeviceNames()

	atLeastOneReason := hasParentTraversal || hasURLEncoding || hasAbsolutePath ||
		hasTildeExpansion || hasColonPattern || hasDeviceName

	assert.True(t, atLeastOneReason,
		"Path %q flagged as vulnerable but no detection method triggered. "+
			"Parent: %v, URL: %v, Absolute: %v, Tilde: %v, Colon: %v, Device: %v",
		path, hasParentTraversal, hasURLEncoding, hasAbsolutePath,
		hasTildeExpansion, hasColonPattern, hasDeviceName)
}

// FuzzAdversarialInputs tests specifically crafted adversarial inputs
func FuzzAdversarialInputs(f *testing.F) {
	// Adversarial patterns designed to bypass common detection methods
	adversarialPatterns := []string{
		// Mixed separators to confuse normalization
		"../\\../etc", "..\\../windows", "..\\/etc/passwd",

		// Null bytes and control characters
		"..\x00/etc/passwd", "file\x00.txt", "..\t/etc",

		// Multiple encoding layers
		"%252e%252e%252f", "%25%32%65%25%32%65%25%32%66",

		// Case variations
		"CON", "con", "Con", "cOn", "coN",
		"PRN", "prn", "Prn", "pRn", "prN",

		// Boundary conditions
		strings.Repeat("../", 100),                   // Very deep traversal
		strings.Repeat("A", 1000) + "/../etc/passwd", // Long filename

		// Unicode normalization attacks
		"..\u002f\u002e\u002e\u002fetc", // Unicode slash and dot
		"\u002e\u002e\u002f",            // Unicode ../
	}

	for _, pattern := range adversarialPatterns {
		f.Add(pattern)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Test that our detection is robust against adversarial inputs
		assert.NotPanics(t, func() {
			result := isVulnerablePath(path)
			// Log for analysis but don't assert specific results
			// since adversarial inputs may have ambiguous expected outcomes
			t.Logf("Adversarial input %q -> vulnerable: %v", path, result)
		}, "Detection should not panic on adversarial input: %q", path)
	})
}

// Helper functions

func createTempZip(t *testing.T, data []byte) string {
	tempFile, err := os.CreateTemp("", "test-*.zip")
	require.NoError(t, err)
	defer tempFile.Close()

	_, err = tempFile.Write(data)
	require.NoError(t, err)

	return tempFile.Name()
}

func verifyZipContents(t *testing.T, zipPath string, expectedFiles []string, expectedContent string) {
	// Read the ZIP file
	data, err := os.ReadFile(zipPath)
	require.NoError(t, err)

	// Create a zip.Reader from the file data
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	// Convert expected files to map for easier lookup
	expectedMap := make(map[string]bool)
	for _, f := range expectedFiles {
		expectedMap[f] = true
	}

	// Check all files in the zip
	for _, f := range zipReader.File {
		if expectedMap[f.Name] || len(expectedFiles) == 0 {
			rc, err := f.Open()
			require.NoError(t, err)

			content, err := io.ReadAll(rc)
			rc.Close()

			require.NoError(t, err)
			assert.Equal(t, expectedContent, string(content),
				"Content mismatch in file: %s", f.Name)

			delete(expectedMap, f.Name)
		}
	}

	// All expected files should have been found and removed from the map
	assert.Empty(t, expectedMap, "Some expected files were not found in the zip")
}
