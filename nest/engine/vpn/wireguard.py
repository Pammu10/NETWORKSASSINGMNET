# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NITK Surathkal

"""Low-level helpers for creating and configuring WireGuard tunnels.

This module keeps all direct CLI interaction with ``wg`` and ``ip`` in one
place, so higher-level topology APIs can focus on orchestration.
"""

import os
import tempfile
from ipaddress import ip_interface
from typing import Optional, Tuple

from nest.engine.exec import exec_subprocess
from nest.engine.ip_link import add_wg_interface as ip_add_wg_interface
from nest.topology.address import Address


def _run_command(cmd: str):
    """Execute a shell command and raise if it fails.

    Parameters
    ----------
    cmd : str
        Command string to execute.

    Returns
    -------
    None
        The function raises ``ValueError`` when command execution fails.
    """

    status = exec_subprocess(cmd, shell=True)
    if status != 0:
        raise ValueError(f"Command failed: {cmd}")


def generate_wg_keypair() -> Tuple[str, str]:
    """Generate a WireGuard private/public keypair.

    Returns
    -------
    Tuple[str, str]
        A tuple ``(private_key, public_key)``.
    """

    with tempfile.NamedTemporaryFile(delete=False) as private_key_file, \
        tempfile.NamedTemporaryFile(delete=False) as public_key_file:
        private_key_path = private_key_file.name
        public_key_path = public_key_file.name

    try:

        cmd = (
            f"wg genkey | tee {private_key_path} "
            f"| wg pubkey > {public_key_path}"
        )
        _run_command(cmd)

        with open(private_key_path, "r", encoding="utf-8") as file:
            private_key = file.read().strip()
        with open(public_key_path, "r", encoding="utf-8") as file:
            public_key = file.read().strip()

        if private_key == "" or public_key == "":
            raise ValueError("Failed to generate WireGuard keypair")

        return private_key, public_key
    finally:
        os.unlink(private_key_path)
        os.unlink(public_key_path)


def add_wg_interface(ns_name: str, interface_name: str):
    """Create a WireGuard network interface inside a namespace.

    Parameters
    ----------
    ns_name : str
        Namespace name where the interface is created.
    interface_name : str
        Name of the WireGuard interface (for example ``wg51820``).
    """

    ip_add_wg_interface(ns_name, interface_name)


def create_wg_interface(ns_name: str, interface_name: str):
    """Backward-compatible alias for ``add_wg_interface``."""

    add_wg_interface(ns_name, interface_name)


def configure_wg_interface(
    ns_name: str,
    interface_name: str,
    private_key: str,
    listen_port: Optional[int] = None,
):
    """Configure local WireGuard interface identity.

    Parameters
    ----------
    ns_name : str
        Namespace in which the interface exists.
    interface_name : str
        Name of the interface to configure.
    private_key : str
        Local private key (base64-encoded key from ``wg genkey``).
    listen_port : int, optional
        UDP listening port. Use ``None`` for peers that should not listen.
    """

    with tempfile.NamedTemporaryFile(delete=False) as key_file:
        key_file_path = key_file.name
        key_file.write(private_key.encode("utf-8"))
        key_file.flush()

    try:
        cmd = (
            f"ip netns exec {ns_name} "
            f"wg set {interface_name} "
            f"private-key {key_file_path}"
        )
        if listen_port is not None:
            cmd += f" listen-port {listen_port}"
        _run_command(cmd)
    finally:
        os.unlink(key_file_path)


def assign_wg_address(ns_name: str, interface_name: str, address: str):
    """Assign an IP address to a WireGuard interface.

    Parameters
    ----------
    ns_name : str
        Namespace containing the interface.
    interface_name : str
        WireGuard interface name.
    address : str
        Address in CIDR format (for example ``10.200.0.1/24``).
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"ip address add {address} dev {interface_name}"
    )
    _run_command(cmd)


# pylint: disable=too-many-arguments
def add_wg_peer(
    ns_name: str,
    interface_name: str,
    peer_public_key: str,
    allowed_ips: str,
    endpoint: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
):
    """Add a peer entry to a WireGuard interface.

    Parameters
    ----------
    ns_name : str
        Namespace containing the local interface.
    interface_name : str
        Local WireGuard interface name.
    peer_public_key : str
        Public key of the remote peer.
    allowed_ips : str
        Comma-separated CIDR list accepted from the peer.
    endpoint : str, optional
        Peer endpoint in ``host:port`` format.
    persistent_keepalive : int, optional
        Keepalive interval in seconds.
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"wg set {interface_name} peer {peer_public_key} "
        f"allowed-ips {allowed_ips}"
    )
    if endpoint is not None:
        cmd += f" endpoint {endpoint}"
    if persistent_keepalive is not None:
        cmd += f" persistent-keepalive {persistent_keepalive}"
    _run_command(cmd)


def remove_wg_peer(ns_name: str, interface_name: str, peer_public_key: str):
    """Remove a peer entry from a WireGuard interface.

    Parameters
    ----------
    ns_name : str
        Namespace containing the local interface.
    interface_name : str
        Local WireGuard interface name.
    peer_public_key : str
        Public key of the peer to remove.
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"wg set {interface_name} peer {peer_public_key} remove"
    )
    _run_command(cmd)


def set_wg_interface_up(ns_name: str, interface_name: str):
    """Bring a WireGuard interface up inside a namespace.

    Parameters
    ----------
    ns_name : str
        Namespace containing the interface.
    interface_name : str
        Name of the WireGuard interface.
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"ip link set dev {interface_name} up"
    )
    _run_command(cmd)


def set_wg_interface_down(ns_name: str, interface_name: str):
    """Bring a WireGuard interface down inside a namespace.

    Parameters
    ----------
    ns_name : str
        Namespace containing the interface.
    interface_name : str
        Name of the WireGuard interface.
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"ip link set dev {interface_name} down"
    )
    _run_command(cmd)


def get_wg_interface_address(ns_name: str, interface_name: str) -> Address:
    """Read IPv4 address from a WireGuard interface.

    Parameters
    ----------
    ns_name : str
        Namespace containing the interface.
    interface_name : str
        Name of the interface.

    Returns
    -------
    Address
        Interface address as an ``Address`` object.
    """

    cmd = (
        f"ip netns exec {ns_name} "
        f"ip -4 -o addr show dev {interface_name}"
    )
    output = exec_subprocess(cmd, shell=True, output=True)
    if output is None or output.strip() == "":
        raise ValueError(
            f"Unable to read address from {interface_name} in namespace {ns_name}"
        )

    # Output format contains: "inet 10.200.0.1/24 ..."
    fields = output.strip().split()
    inet_idx = fields.index("inet")
    interface_addr = fields[inet_idx + 1]

    # Address class normalizes the value and validates input.
    normalized_addr = ip_interface(interface_addr)
    return Address(str(normalized_addr))
