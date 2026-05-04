# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019-2023 NITK Surathkal

"""
The vpn sub-package provides low-level APIs
for emulating a virtual private network.

Sub-modules:
------------
pki : PKI management functions for generating certificates,
      keys, and certificate authorities
client : Functions for running an OVPN client
server : Functions for running an OVPN server
wireguard : Functions for creating and managing WireGuard interfaces
"""

from .pki import (
    init_pki,
    build_ca,
    build_dh,
    build_client_keypair,
    build_server_keypair,
)
from .server import run_ovpn_server
from .client import run_ovpn_client
from .wireguard import (
    generate_wg_keypair,
    add_wg_interface,
    create_wg_interface,
    configure_wg_interface,
    assign_wg_address,
    add_wg_peer,
    remove_wg_peer,
    set_wg_interface_up,
    set_wg_interface_down,
    get_wg_interface_address,
)
