"""Input validation and security constants shared by all tool handlers."""

from pathlib import Path

# Hard caps applied to every tool that accepts a count or duration. These exist
# to keep tshark output bounded so we don't burn LLM context or hang the client.
MAX_PACKET_COUNT = 10000
MAX_DURATION_SECONDS = 300  # 5 minutes
ALLOWED_FILE_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def validate_file_path(file_path: str) -> Path:
    """Validate and sanitize a pcap file path.

    Rejects path traversal and any extension outside ``ALLOWED_FILE_EXTENSIONS``.

    Args:
        file_path: The file path to validate.

    Returns:
        Resolved Path object.

    Raises:
        ValueError: If the path is invalid or potentially malicious.
    """
    try:
        if ".." in str(file_path):
            raise ValueError("Path traversal not allowed")

        path = Path(file_path).resolve()

        if path.suffix.lower() not in ALLOWED_FILE_EXTENSIONS:
            raise ValueError(
                f"Invalid file extension. Allowed: {', '.join(ALLOWED_FILE_EXTENSIONS)}"
            )

        return path
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid file path: {e}") from e


def validate_display_filter(filter_expr: str) -> str:
    """Reject shell metacharacters in a Wireshark display filter.

    Comparison operators (``>``, ``<``, ``>=``, ``<=``) and the boolean tokens
    ``&&``/``||`` are legitimate Wireshark display-filter syntax — e.g.
    ``goose.stNum > 0`` or ``tcp.flags.syn == 1 && tcp.flags.ack == 0``. They
    are safe here because every tshark invocation goes through
    ``asyncio.create_subprocess_exec`` with an explicit argv, so the shell
    never sees them.

    What we still reject are the characters that could break out of an argv
    element if the value ever did reach a shell: ``;``, backtick, command
    substitution (``$(``, ``${``), and bare newlines.

    Args:
        filter_expr: The filter expression to validate.

    Returns:
        The same expression if safe.

    Raises:
        ValueError: If the filter contains potentially dangerous content.
    """
    if not filter_expr:
        return filter_expr

    dangerous_patterns = [";", "`", "$(", "${", "\n", "\r"]
    for pattern in dangerous_patterns:
        if pattern in filter_expr:
            raise ValueError(f"Invalid character in display filter: {pattern}")

    if len(filter_expr) > 1000:
        raise ValueError("Display filter too long (max 1000 characters)")

    return filter_expr
