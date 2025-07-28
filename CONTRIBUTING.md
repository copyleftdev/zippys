# Contributing to Zippys

Thank you for your interest in contributing to Zippys! This document provides guidelines for contributing to this security research tool.

## Code of Conduct

This project is intended for legitimate security research and authorized testing only. All contributors must:

- Use the tool only for authorized security testing
- Respect responsible disclosure practices
- Follow ethical security research guidelines
- Not use the tool for malicious purposes

## Development Setup

1. **Prerequisites**
   - Go 1.21 or later
   - Git
   - Make (for using the Makefile)

2. **Clone and Setup**
   ```bash
   git clone https://github.com/copyleftdev/zippys.git
   cd zippys
   make deps
   ```

3. **Development Workflow**
   ```bash
   # Full development build
   make dev
   
   # Quick build for testing
   make quick
   
   # Run tests
   make test
   
   # Run comprehensive tests including fuzz testing
   make test-all
   ```

## Project Structure

```
zippys/
├── main.go              # Main application and detection logic
├── main_test.go         # Comprehensive test suite
├── Makefile            # Build and development workflow
├── README.md           # Project documentation
├── go.mod              # Go module definition
├── media/              # Branding and logo assets
├── testdata/           # Rich test data collection
└── run_testdata.sh     # Test data validation script
```

## Testing

We maintain high testing standards with multiple test types:

### Unit Tests
```bash
make test
```

### Fuzz Testing
```bash
make fuzz
```

### Integration Tests
```bash
make run-tests
make test-data
```

### Coverage Reports
```bash
make coverage
```

## Code Quality

Before submitting contributions:

1. **Format Code**
   ```bash
   make fmt
   ```

2. **Vet Code**
   ```bash
   make vet
   ```

3. **Run Linter** (if available)
   ```bash
   make lint
   ```

4. **Security Scan** (if available)
   ```bash
   make security
   ```

## Contribution Guidelines

### Bug Reports

When reporting bugs, please include:

- Go version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Any relevant log output

### Feature Requests

For new features:

- Describe the use case
- Explain why it's needed for security research
- Consider security implications
- Provide implementation suggestions if possible

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test thoroughly**
   ```bash
   make test-all
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: add new detection pattern for X"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Detection Logic Contributions

When contributing to the path traversal detection logic:

1. **Understand the State Machine**
   - Review the `PathVulnerabilityAnalyzer` structure
   - Understand the tokenization process
   - Study existing detection methods

2. **Add Comprehensive Tests**
   - Include edge cases in test suite
   - Add fuzz test cases for new patterns
   - Verify no false positives/negatives

3. **Document New Patterns**
   - Explain the vulnerability pattern
   - Provide examples
   - Reference security advisories if applicable

## Test Data Contributions

When adding new test data:

1. **Organize by Category**
   - `testdata/vulnerable/` - Known vulnerable patterns
   - `testdata/safe/` - Legitimate paths
   - `testdata/mixed/` - Mixed scenarios
   - `testdata/adversarial/` - Bypass attempts

2. **Document Test Cases**
   - Update `testdata/README.md`
   - Explain the attack vector
   - Provide expected results

## Security Considerations

- Never commit real sensitive data
- Use placeholder content in test files
- Ensure all examples are for educational purposes
- Follow responsible disclosure for any vulnerabilities found

## Release Process

Releases follow semantic versioning:

- **Major**: Breaking changes to API or detection logic
- **Minor**: New features, detection patterns
- **Patch**: Bug fixes, documentation updates

## Getting Help

- Check existing issues and documentation
- Review the comprehensive test suite for examples
- Use the project's discussion features
- Follow security research best practices

## Recognition

Contributors will be recognized in:

- CHANGELOG.md for their contributions
- README.md contributors section
- Release notes for significant contributions

Thank you for helping make Zippys a better security research tool!
