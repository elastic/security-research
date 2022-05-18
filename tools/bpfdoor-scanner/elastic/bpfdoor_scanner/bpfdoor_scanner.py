#!/usr/bin/env /usr/bin/python3
import logging
from importlib.metadata import version
from ipaddress import IPv4Address
from os import geteuid
from socket import (
    AF_INET,
    SO_REUSEADDR,
    SOCK_DGRAM,
    SOL_SOCKET,
    gethostbyname,
    gethostname,
    htons,
)
from socket import inet_aton as a2n
from socket import socket
from sys import byteorder, platform, stderr
from typing import Optional

import typer

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import IP, UDP, Raw, send  # noqa: E402

logger = logging.getLogger(__name__)

TIMEOUT: int = 5  # in seconds, how long to wait for reply
DEFAULT_SOURCE_IP: str = gethostbyname(gethostname())


def version_callback(value: bool):
    _ver = version("bpfdoor-scanner")
    if value:
        typer.echo(f"Elastic BPFDoor Scanner Version: {_ver}")
        raise typer.Exit(code=1)


def validate_ipaddr(value: str) -> str:
    try:
        _val: IPv4Address = IPv4Address(value)
    except ValueError:
        raise typer.BadParameter(f"{value} is not a valid IPv4 address!")

    return f"{_val}"


def has_admin_rights() -> bool:
    is_admin: bool = False

    if platform == "linux":
        import pyprctl

        _caps: list[pyprctl.Cap] = [pyprctl.Cap.NET_BIND_SERVICE, pyprctl.Cap.NET_RAW]
        is_admin = pyprctl.cap_effective.has(*_caps)

        logger.info(f"Process has these permissions: {pyprctl.cap_effective}")
    else:
        is_admin = geteuid() == 0
    return is_admin


def is_local_ip(value: str) -> bool:
    """
    Checks local interfaces to see if IP given is a
    local IP. Useful to know when trying to bind a
    port on a particular interface
    """
    import netifaces

    is_local: bool = False
    for entry in netifaces.interfaces():
        item = netifaces.ifaddresses(entry).get(netifaces.AF_INET, None)
        if item and any([True for x in item if x["addr"] == value]):
            is_local = True
            break

    return is_local


def encodeport(port: int) -> bytes:
    """
    Takes 53, returns b'\x00\x35'
    """
    return htons(port).to_bytes(2, byteorder)


def send_ping(
    target_ip: str,
    target_port: int,
    reply_ip: str,
    reply_port: int,
    verbose: bool = False,
) -> None:
    logger.info(f"Sending UDP packet to {target_ip}:{target_port} from {reply_ip}")
    send(
        IP(dst=target_ip)
        / UDP(dport=target_port)
        / Raw(load=b"rU\x00\x00" + a2n(reply_ip) + encodeport(reply_port)),
        verbose=verbose,
    )


def do_bind(ip: str, port: int) -> socket:
    s = socket(family=AF_INET, type=SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    _bind_ip: str = "0.0.0.0"
    if is_local_ip(ip):
        _bind_ip = ip
    else:
        logger.info(f"Listening on all interfaces since {ip} isn't on any interface")

    logger.info(f"Binding UDP socket on {_bind_ip}:{port}")
    s.bind((_bind_ip, port))

    return s


def recv(sock: socket, timeout: int) -> None:
    sock.settimeout(timeout)
    try:
        response = sock.recvfrom(1)
    except TimeoutError:
        logger.error(f"No reply within {timeout} seconds")
        raise typer.Exit(code=3)
    msg = response[0]
    remote = response[1]
    if msg == b"1":
        print(f"bpfdoor at {remote[0]} responded from port {remote[1]}")


def main(
    target_ip: str = typer.Option(..., callback=validate_ipaddr),
    target_port: int = typer.Option(68),
    source_ip: str = typer.Option(
        DEFAULT_SOURCE_IP,
        callback=validate_ipaddr,
        help="IP for target to respond to and attempt to bind locally",
    ),
    source_port: int = typer.Option(53, help="Local port to listen on for response"),
    timeout: int = typer.Option(TIMEOUT, help="Number of seconds to wait for response"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose output"),
    debug: bool = typer.Option(False, "-d", "--debug", help="Show debug output"),
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback
    ),
) -> None:
    """
    Sends a discovery packet to suspected BPFDoor endpoints.

    Example usage:

        sudo bpfdoor-scanner --target-ip 1.2.3.4

    Sends a packet to IP 1.2.3.4 using the default target port 68/UDP (tool listens on all ports)
    using the default interface on this host and listens on port 53/UDP to masquerade as
    traffic.

    NOTE: Elevated privileges are required for source ports < 1024.
    """

    if verbose:
        logger.setLevel(logging.INFO)
    if debug:
        logger.setLevel(logging.DEBUG)

    if source_port < 1024 and not has_admin_rights():
        logger.fatal("Need root to bind a port below 1024")
        raise typer.Exit(code=2)

    sock = do_bind(source_ip, source_port)
    send_ping(target_ip, target_port, source_ip, source_port, verbose=(verbose | debug))
    recv(sock, timeout)


def run():
    logging.basicConfig(stream=stderr, format="%(message)s", level=logging.WARN)
    app = typer.Typer(add_completion=False)
    app.command()(main)
    app()


if __name__ == "__main__":
    run()
