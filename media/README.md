# Zippys Media Assets

This directory contains branding and visual assets for the Zippys Zip Slip Security Tool.

## Directory Structure

```
media/
├── logos/          # ASCII art logos in various formats
├── banners/        # Header banners and promotional graphics
├── icons/          # Compact icons and symbols
└── README.md       # This documentation
```

## Logo Assets

### Main Logo (`logos/zippys_logo.txt`)
The primary ASCII art logo used in the CLI application header.

### Compact Logo (`logos/zippys_compact.txt`)
A boxed version of the logo suitable for documentation and presentations.

### Project Logo (`logos/project_logo.txt`)
A comprehensive project logo with full branding and feature highlights.

## Banner Assets

### Security Banner (`banners/security_banner.txt`)
Professional security-themed banner highlighting key features and warnings.

### CLI Header (`banners/cli_header.txt`)
Streamlined header banner optimized for command-line interface display.

## Icon Assets

### Zippys Icon (`icons/zippys_icon.txt`)
Minimalist icon representation suitable for compact displays.

## Usage

### In CLI Applications
```go
// Display main logo
fmt.Print(readLogoFile("media/logos/zippys_logo.txt"))

// Display CLI header
fmt.Print(readLogoFile("media/banners/cli_header.txt"))
```

### In Documentation
Copy and paste the ASCII art from the appropriate files into:
- README.md files
- Documentation headers
- Presentation materials
- Security reports

### In Terminal Output
The logos are designed to work well with:
- Standard terminal fonts
- Colored output (using ANSI color codes)
- Various terminal widths
- Both light and dark terminal themes

## Design Principles

- **Professional**: Clean, security-focused aesthetic
- **Readable**: Clear typography in monospace fonts
- **Scalable**: Multiple size variants for different use cases
- **Consistent**: Unified branding across all assets
- **Terminal-Friendly**: Optimized for command-line environments

## Color Schemes

The ASCII art is designed to work with these color schemes:
- **Primary**: Blue/Cyan for main text
- **Accent**: Yellow/Gold for highlights
- **Warning**: Red for security warnings
- **Success**: Green for positive feedback

## Author

copyleftdev

## License

These media assets are part of the Zippys project and are provided for educational and research purposes only.
