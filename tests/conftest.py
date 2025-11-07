"""Test configuration."""

import pytest


@pytest.fixture
def sample_pcap_path() -> str:
    """Return path to a sample pcap file for testing."""
    return "/tmp/test.pcap"
