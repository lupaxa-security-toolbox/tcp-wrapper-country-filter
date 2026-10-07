#!/usr/bin/env python3
"""TCP Wrapper country filter.

Set ``ACTION``, ``BAN_LIST``, and ``DATABASE``. Exit 0 allows the connection.
Exit 1 denies it.

The multiplexer calls this filter as ``country-filter <client-ip> MUX``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import sys
import syslog
from pathlib import Path

import maxminddb

__version__ = "0.0.0"

ALLOW_ACTION = "ALLOW"
DENY_ACTION = "DENY"

# Space-separated or comma-separated values matched by check_results.
BAN_LIST = ""

# DENY blocks a listed value. ALLOW blocks a value that is not listed.
ACTION = DENY_ACTION

# IPinfo Lite MMDB written by ipinfo-update. country_code is the two-letter code.
DATABASE = Path("/var/lib/ipinfo/ipinfo_lite.mmdb")

IP = ""
MUX = False


def get_version() -> str:
    """Return the package version string."""
    return __version__


def in_multiplexer() -> bool:
    """Return whether the multiplexer started this filter."""
    return MUX


def in_terminal() -> bool:
    """Return whether stdout is a terminal."""
    return sys.stdout.isatty()


def debug(message: str = "") -> None:
    """Print when a person or the multiplexer can see it, and log the message."""
    if not message:
        return
    if in_terminal() or in_multiplexer():
        print(message)
    with contextlib.suppress(OSError):
        syslog.syslog(message)


def _listed(item: str, ban_list: str) -> bool:
    tokens = {token.casefold() for token in ban_list.replace(",", " ").split() if token}
    return item.casefold() in tokens


def check_results(item: str, ban_list: str) -> None:
    """Deny the connection when ``item`` fails the ``ACTION`` rule.

    Parameters
    ----------
    item :
        Value returned by :func:`lookup`, such as an ASN or a country code.
    ban_list :
        Space-separated or comma-separated values to match.
    """
    matched = _listed(item, ban_list)
    if ACTION == DENY_ACTION:
        response = DENY_ACTION if matched else ALLOW_ACTION
    else:
        response = ALLOW_ACTION if matched else DENY_ACTION
    if response == DENY_ACTION:
        debug(f"{response} sshd connection from {IP} ({item}) version {__version__}")
        raise SystemExit(1)


def validate_ip(ip_address: str) -> str:
    """Validate and normalise an IPv4 or IPv6 address.

    Parameters
    ----------
    ip_address :
        Address to check.

    Returns
    -------
    str
        Normalised address.
    """
    return str(ipaddress.ip_address(ip_address))


def lookup(ip: str) -> str:
    """Return the ISO 3166-1 alpha-2 country code for this client address.

    Parameters
    ----------
    ip :
        Client address from TCP Wrappers.

    Returns
    -------
    str
        Two-letter country code, or an empty string when the address has
        none, the address is invalid, or the database is missing.
    """
    try:
        ip_address = validate_ip(ip)
    except ValueError:
        debug(f"Invalid IP address: {ip}")
        return ""

    try:
        with maxminddb.open_database(DATABASE) as reader:
            record = reader.get(ip_address)
    except FileNotFoundError:
        debug(f"IPinfo database not found: {DATABASE}")
        return ""

    if not isinstance(record, dict):
        return ""

    country_code = record.get("country_code")
    if not isinstance(country_code, str) or not country_code:
        return ""

    return country_code


def handle_blocks() -> None:
    """Look up the client and apply the allow or deny rule."""
    check_results(lookup(IP), BAN_LIST)


def main(argv: list[str] | None = None) -> None:
    """Run the filter for one client address.

    Parameters
    ----------
    argv :
        Arguments after the program name. ``--version`` prints the filter
        version. Otherwise the first argument is the client address, and a
        second argument means the multiplexer started this filter.
    """
    global IP, MUX

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"--version", "-V"}:
        print(f"country-filter {__version__}")
        raise SystemExit(0)

    if not args or not args[0]:
        debug("Ip addressed not supplied - Aborting")
        raise SystemExit(0)

    IP = args[0]
    MUX = len(args) > 1 and bool(args[1])
    handle_blocks()
    raise SystemExit(0)


if __name__ == "__main__":
    main()
