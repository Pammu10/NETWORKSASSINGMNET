# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NITK Surathkal

"""High-level API implementation for WireGuard VPN tunnels."""

from ipaddress import ip_interface, ip_network
from typing import List

from nest.engine.vpn import (
    generate_wg_keypair,
    add_wg_interface,
    configure_wg_interface,
    assign_wg_address,
    add_wg_peer,
    WireGuardPeerConfig,
    set_wg_interface_up,
    get_wg_interface_address,
)
from nest.topology.network import Network
from nest.topology import Node
from nest.topology.interface import BaseInterface
from nest.topology.device import Device
from nest.engine.util import is_dependency_installed


def _validate_port(port: int):
    """Validate a WireGuard UDP port.

    Parameters
    ----------
    port : int
        UDP port value used for WireGuard listener.

    Returns
    -------
    None
        Raises ``ValueError`` if the value is outside [0, 65535].
    """

    if not 0 <= port <= 65535:
        raise ValueError("Invalid port number")


def _allocate_endpoint_addresses(network: Network, endpoint_count: int) -> List[str]:
    """Allocate endpoint addresses from the given VPN subnet.

    Parameters
    ----------
    network : Network
        VPN network from which endpoint IPs are allocated.
    endpoint_count : int
        Number of endpoint addresses required.

    Returns
    -------
    List[str]
        Allocated endpoint addresses in CIDR notation.
    """

    subnet = ip_network(network.net_address.get_addr(), strict=False)
    hosts = list(subnet.hosts())
    if endpoint_count > len(hosts):
        raise ValueError(
            f"VPN network {subnet} does not have enough usable addresses "
            f"for {endpoint_count} endpoints"
        )
    prefix_len = subnet.prefixlen
    return [f"{host}/{prefix_len}" for host in hosts[:endpoint_count]]


def _build_tunnel_interface(node: Node, interface_name: str, address: str) -> BaseInterface:
    """Create a topology ``BaseInterface`` object for a tunnel endpoint.

    Parameters
    ----------
    node : Node
        Node that owns the tunnel interface.
    interface_name : str
        WireGuard interface name.
    address : str
        Endpoint address in CIDR notation.

    Returns
    -------
    BaseInterface
        Interface object mapped to the node and configured address.
    """

    tunnel_interface = BaseInterface(interface_name, Device(node.name, node.id))
    tunnel_interface.set_address(address)
    return tunnel_interface


def _validate_peers(peers):
    """Validate WireGuard peers list.

    Parameters
    ----------
    peers : List[Node]
        Nodes that should participate in the WireGuard overlay.

    Returns
    -------
    None
        Raises ``ValueError`` when the peers list is invalid.
    """

    if len(peers) < 2:
        raise ValueError("At least two peers are required for WireGuard connection")

    for peer in peers:
        if len(peer.interfaces) == 0:
            raise ValueError(
                f"Peer {peer.name} has no underlay interface. "
                "Create normal topology links before connect_wireguard()."
            )


# pylint: disable=too-many-locals
def connect_wireguard(
    *peers: Node,
    network: Network,
    port: int = 51820,
    persistent_keepalive: int = 25,
):
    """Create a WireGuard VPN overlay between multiple peers.

    This API sets up a full-mesh peer configuration. Every peer is configured
    with every other peer, including explicit endpoint information, enabling
    seamless bidirectional communication without traffic warm-up.

    Parameters
    ----------
    *peers : Node
        Two or more nodes participating in the WireGuard overlay.
    network : Network
        VPN endpoint address pool.
    port : int, optional
        UDP listen port for every peer WireGuard interface, defaults to ``51820``.
    persistent_keepalive : int, optional
        Keepalive interval in seconds configured for every remote peer,
        defaults to ``25``.

    Returns
    -------
    Tuple[BaseInterface]
        Tunnel interfaces in the same order as input peers.
    """

    _validate_port(port)
    _validate_peers(peers)

    required_tools = ["wg", "ip"]
    for tool in required_tools:
        if not is_dependency_installed(tool):
            raise ValueError(
                f"{tool} is not installed.\n Install WireGuard tools using "
                "'sudo apt install wireguard-tools'"
            )

    endpoint_count = len(peers)
    endpoint_addresses = _allocate_endpoint_addresses(network, endpoint_count)

    wg_interface_name = f"wg{port}"

    peer_configs = []

    for index, peer in enumerate(peers):
        peer_private_key, peer_public_key = generate_wg_keypair()
        peer_address = endpoint_addresses[index]
        peer_underlay_ip = peer.interfaces[0].get_address().get_addr(with_subnet=False)
        peer_tunnel_ip = str(ip_interface(peer_address).ip)

        add_wg_interface(peer.id, wg_interface_name)
        configure_wg_interface(peer.id, wg_interface_name, peer_private_key, port)
        assign_wg_address(peer.id, wg_interface_name, peer_address)

        peer_configs.append(
            {
                "node": peer,
                "public_key": peer_public_key,
                "tunnel_ip": peer_tunnel_ip,
                "endpoint": f"{peer_underlay_ip}:{port}",
            }
        )

    for local_index, local_peer in enumerate(peer_configs):
        for remote_index, remote_peer in enumerate(peer_configs):
            if local_index == remote_index:
                continue
            add_wg_peer(
                local_peer["node"].id,
                wg_interface_name,
                remote_peer["public_key"],
                WireGuardPeerConfig(
                    allowed_ips=f"{remote_peer['tunnel_ip']}/32",
                    endpoint=remote_peer["endpoint"],
                    persistent_keepalive=persistent_keepalive,
                ),
            )

    tun_interfaces = []
    for peer_cfg in peer_configs:
        set_wg_interface_up(peer_cfg["node"].id, wg_interface_name)
        peer_wg_address = get_wg_interface_address(peer_cfg["node"].id, wg_interface_name)
        tun_interfaces.append(
            _build_tunnel_interface(
                peer_cfg["node"], wg_interface_name, peer_wg_address.get_addr()
            )
        )

    return tuple(tun_interfaces)
