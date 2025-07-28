# ZipSlip Security Tool

<div align="center">
  <img src="media/zippylogo.png" alt="Zippys Logo" width="200">
</div>

A security tool for detecting, testing, and exploiting Zip Slip vulnerabilities. This tool is designed for security research and penetration testing purposes only.

## Features

- Generate malicious ZIP files with path traversal payloads
- Test systems for Zip Slip vulnerabilities in a controlled environment
- Scan directories for potentially vulnerable ZIP files
- Detailed reporting of vulnerable files and paths
- Safe testing mode to prevent accidental damage

## Installation

1. Ensure you have Go 1.21 or later installed
2. Clone this repository
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Build the tool:
   ```bash
   go build -o zippys
   ```

## Usage

```
Usage: zippys -m|--mode MODE [options]

Advanced Zip Slip Security Tool

Options:
  -m, --mode MODE     Operation mode: 'generate', 'test', or 'scan' (required)
  -d, --dir DIR       Target directory for scanning or testing (default: .)
  -o, --output FILE   Output file for malicious ZIP (default: malicious.zip)
  -p, --path PATH     Malicious path for ZIP slip (e.g., '../../evil.txt') (default: ../../evil.txt)
  -c, --content TEXT  Content for the malicious file (default: This is a malicious payload for Zip Slip testing)
  -t, --test          Test mode (safer for experimentation)
  -v, --verbose       Enable verbose output
  -h, --help          Display this help message
```

## Examples

### Generate a malicious ZIP file
```bash
./zippys -m generate -o payload.zip -p "../../../etc/passwd" -c "malicious content"
```

### Test if a system is vulnerable to Zip Slip
```bash
./zippys -m test -v
```

### Scan a directory for vulnerable ZIP files
```bash
./zippys -m scan -d /path/to/scan
```

## Security Considerations

- This tool is for authorized security testing and research purposes only
- Always obtain proper authorization before testing systems you don't own
- Use the `-t/--test` flag when experimenting to prevent accidental damage
- The tool includes safety checks, but use with caution

## License

This tool is provided for educational and research purposes only. Use responsibly and only on systems you have permission to test.

## Author

copyleftdev
