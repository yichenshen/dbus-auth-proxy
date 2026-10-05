#!/usr/bin/python3
"""
dbus-auth-proxy is a proxy that sets up a bi-directional proxy between a socket
that it creates the the system_dbus.

It then rewrite the AUTH EXTERNAL message's UID to it's owner's UID.

This is meant for apps running in containers that need to access dbus but do not
or can not run in userns=keep-id mode. In such cases clients which formulate
the AUTH EXTERNAL message will use the UID inside the container, often 0. When
the request routes out of the container the socket's UID will be different,
leading to auth failures.

Instead, we can run dbus-auth-proxy in a container using userns=keep-id since
there's no requirement for dbus-auth-proxy to run as root. Then we mount the
socket created by dbus-auth-proxy to the target app's /run/dbus so that the
target app will send system dbus requests to dbus-auth-proxy. dbus-auth-proxy
will then check the connection's UID matches it's own. This ensure that the
proxy does not grant any privileges that the connector doesn't already have. It
then fixes the AUTH EXTERNAL UID to it's own as well as open a connection to
the true system dbus.

All three UID (client connection/AUTH/dbus connection) will then be seen as the
same both inside and outside containers.

All remaining data is forward directly without modification both ways.
"""

from typing import Awaitable, Callable, Optional

from socket import SO_PEERCRED, SOL_SOCKET
from asyncio import StreamReader, StreamWriter

import asyncio
import logging
import os
import re
import signal
import struct

from opts import Options, get_opts

PROCESS_UID = os.getuid()
REPLACEMENT_UID_HEX = str(PROCESS_UID).encode("ascii").hex().encode()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_socket_uid(writer: StreamWriter) -> Optional[int]:
    """
    Pulls out the UID of the client of the socket backing writer.

    Args:
        writer (StreamWriter): The writer for the socket of the connection
    Returns:
        Optional[int]: The UID of the client of the connection if found
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return None

    try:
        peercred_bytes = sock.getsockopt(
            SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i")
        )
        _, uid, _ = struct.unpack("3i", peercred_bytes)
        return uid
    except (OSError, struct.error) as e:
        logging.error(
            f"Could not get peer user id from socket, connection will be closed: {e}"
        )
        return None


def verify_and_transform(data: bytes, socket_uid: int) -> bytes:
    """
    Checks the socket uid is the same as our own and overwrites the dbus AUTH
    UID to our own if so.

    Transformation will only happen if the UID check passes *and* a UID is
    provided in the AUTH message. If the AUTH does not have an UID, this function
    will not add one.

    Args:
        data (bytes): The data for the dbus AUTH message
        socket_uid (int): The uid of the socket client
    Returns:
        A transformed AUTH message if applicable, or the original message
        otherwise.
    """
    logging.debug(
        f"Verifying socket's user: {socket_uid} with proxy's user: {PROCESS_UID}"
    )
    if socket_uid != PROCESS_UID:
        raise PermissionError(
            f"Permission denied by proxy: Client UID ({socket_uid}) != Proxy UID ({PROCESS_UID})"
        )

    return re.sub(
        b"\x00AUTH EXTERNAL \\d+",
        b"\x00AUTH EXTERNAL " + REPLACEMENT_UID_HEX,
        data,
    )


async def forward(
    from_stream: StreamReader, to_stream: StreamWriter, buffer_size: int
) -> None:
    """
    Forwards data from one stream to another with bufferring.

    Args:
        from_stream (StreamReader): The stream to forward from
        to_stream (StreamReader): The stream to forward to
        buffer_size (int): Size of the buffer to use
    """
    while not from_stream.at_eof():
        data = await from_stream.read(buffer_size)
        if not data:
            break
        to_stream.write(data)
        await to_stream.drain()

    await to_stream.drain()


async def handle_client(
    auth_data: bytes,
    upstream_reader: StreamReader,
    upstream_writer: StreamWriter,
    dbus_soc: str,
    buffer_size: int,
) -> None:
    """
    Handles the client connection by opening a connection to the real dbus socket
    and setting up a bi-directional forward to and from the real socket to the
    client.

    The initial auth_data will have it's UID fixed and sent through the dbus
    connection before the two sides are connected.

    Function will exit after the interaction from the client ends.

    Args:
        auth_data (bytes): The firest message from the client, the AUTH message
        upstream_reader (streamreader): reader of data from the client
        upstream_writer (streamwriter): writer of data to the client
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    """
    logging.debug(f"Opening connection to system dbus at: {dbus_soc}")
    (downstream_reader, downstream_writer) = (
        await asyncio.open_unix_connection(path=dbus_soc)
    )

    logging.debug("dbus connection established, fowarding AUTH message")
    downstream_writer.write(auth_data)
    await downstream_writer.drain()

    dbus_to_client = asyncio.create_task(
        forward(downstream_reader, upstream_writer, buffer_size)
    )
    client_to_dbus = asyncio.create_task(
        forward(upstream_reader, downstream_writer, buffer_size)
    )

    logging.debug("Bi-directional stream established")
    await asyncio.wait(
        {dbus_to_client, client_to_dbus}, return_when=asyncio.FIRST_COMPLETED
    )
    logging.debug("Bi-directional stream ended")

    downstream_writer.close()
    await downstream_writer.wait_closed()
    logging.debug("System dbus connection closed")


async def client_callback(
    reader: StreamReader, writer: StreamWriter, dbus_soc: str, buffer_size: int
) -> None:
    """
    Callback to handle a new client connection.

    Reads the initial auth message, transforms the UID, then blindly forwards
    data both ways after that.

    Args:
        reader (streamreader): reader of data from the client
        writer (streamwriter): writer of data to the client
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    """
    logging.debug("Accepted connection from client")
    socket_uid = get_socket_uid(writer)
    logging.debug(f"Client user id: {socket_uid}")
    if socket_uid is None:
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    try:
        auth_data = await reader.readline()
        auth_data = verify_and_transform(auth_data, socket_uid)

        logging.debug(f"Verification complete and UID fixed to {PROCESS_UID}")
        logging.debug("Will begin forwarding data")

        await handle_client(auth_data, reader, writer, dbus_soc, buffer_size)
    except PermissionError as e:
        logging.warning(f"Permission Denied: {e}")
    finally:
        await writer.drain()
        writer.close()
        await writer.wait_closed()


def gen_client_callback(
    dbus_soc: str, buffer_size: int
) -> Callable[[StreamReader, StreamWriter], Awaitable[None]]:
    """
    Higher order function that generates a callback for the client connection
    acceptor, meant to be used with asyncio's start_unix_server.

    This function bascially bakes in context required to handle forwarding and
    returns a function that only takes in reader and writer from the client
    socket.

    Args:
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    Returns:
        Callable[[StreamReader, StreamWriter], Awaitable[None]]:
            A callback suitable for the server acceptor
    """

    async def callback(reader: StreamReader, writer: StreamWriter) -> None:
        await client_callback(reader, writer, dbus_soc, buffer_size)

    return callback


async def run_proxy(opts: Options) -> None:
    """
    Starts the proxy server and starts accepting dbus connections like a real
    dbus socket.

    Connections will trigger another connection to the real dbus socket and data
    will be proxied to that after the AUTH message is fixed.

    Args:
        opts (Options): Options for the proxy
    """
    if os.path.exists(opts.client_socket):
        os.remove(opts.client_socket)

    handle_client = gen_client_callback(opts.system_dbus, opts.buffer_size)
    server = await asyncio.start_unix_server(
        handle_client, path=opts.client_socket
    )

    logging.info(f"Proxy listening on {opts.client_socket}")
    logging.info(f"Forwarding to {opts.system_dbus}")

    await server.serve_forever()


def handle_sigterm(signum, frame) -> None:
    """
    Treats SIGTERM like Ctrl-C. As PID 1 in a container the process has no
    default SIGTERM handler, so without this `podman stop` has to SIGKILL it.
    Further SIGTERMs are ignored so they can't interrupt the shutdown cleanup.
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


if __name__ == "__main__":
    opts = get_opts()
    signal.signal(signal.SIGTERM, handle_sigterm)
    try:
        if os.path.exists(opts.client_socket):
            os.remove(opts.client_socket)
        asyncio.run(run_proxy(opts))
    except KeyboardInterrupt as e:
        logging.info("Shutting Down")
    finally:
        if os.path.exists(opts.client_socket):
            os.remove(opts.client_socket)
