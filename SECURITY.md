# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Considerations

### Network Capture Permissions

- **Live Capture**: Requires elevated permissions on most systems
  - Linux: User must be in the `wireshark` group or run as root
  - macOS: Requires BPF device access
  - Windows: May require administrator privileges

### Input Validation

This MCP server implements security measures to prevent:

- **Path Traversal**: File paths are validated and resolved
- **Command Injection**: Display filters are sanitized
- **Resource Exhaustion**: Packet counts and capture durations are limited

### Safe Defaults

- Maximum packet count: 10,000 packets
- Maximum capture duration: 300 seconds (5 minutes)
- Only `.pcap`, `.pcapng`, and `.cap` files are allowed

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **Do NOT** open a public issue
2. Use GitHub's "Report a vulnerability" feature to create a private security advisory: https://github.com/khuynh22/mcp-wireshark/security/advisories/new
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Best Practices for Users

1. **Run with minimal privileges** - Only grant necessary permissions
2. **Review capture locations** - Be aware of what network interfaces are being captured
3. **Secure PCAP files** - Capture files may contain sensitive data
4. **Keep dependencies updated** - Regularly update tshark and this package

## Dependency Security

This project uses:

- `mcp` - Official MCP SDK
- `pyshark` - Python wrapper for tshark
- Standard library modules for core functionality

All dependencies are pinned and regularly audited.
