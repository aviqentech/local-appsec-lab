"""Verified TLS with platform/user roots plus the maintained Mozilla CA bundle."""

import ssl

import certifi


def context() -> ssl.SSLContext:
    result = ssl.create_default_context()
    result.load_verify_locations(cafile=certifi.where())
    return result
