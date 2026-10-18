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

All remaining data, including file descriptors passed along with it, is
forwarded directly without modification both ways.
"""

from array import array
from typing import Awaitable, Callable, List, Optional, Tuple

from socket import SCM_RIGHTS, SO_PEERCRED, SOL_SOCKET

import asyncio
import logging
import os
import re
import signal
import socket
import struct

from opts import Options, get_opts

PROCESS_UID = os.getuid()
REPLACEMENT_UID_HEX = str(PROCESS_UID).encode("ascii").hex().encode()
# Most file descriptors the kernel passes in a single message (SCM_MAX_FD).
MAX_FDS = 253
# Same limit dbus-daemon applies to an auth line. The first line is read
# before the client's UID is rejected, so it must be bounded.
MAX_AUTH_LINE = 16 * 1024

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_socket_uid(sock: socket.socket) -> Optional[int]:
    """
    Pulls out the UID of the client of the socket.

    Args:
        sock (socket): The socket of the connection
    Returns:
        Optional[int]: The UID of the client of the connection if found
    """
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


async def wait_ready(sock: socket.socket, writable: bool) -> None:
    """
    Waits until the non-blocking socket is readable (or writable).

    Args:
        sock (socket): The socket to wait on
        writable (bool): Wait for writability instead of readability
    """
    loop = asyncio.get_running_loop()
    ready = loop.create_future()
    add, remove = (
        (loop.add_writer, loop.remove_writer)
        if writable
        else (loop.add_reader, loop.remove_reader)
    )
    add(sock.fileno(), lambda: ready.done() or ready.set_result(None))
    try:
        await ready
    finally:
        remove(sock.fileno())


async def recv_with_fds(
    sock: socket.socket, buffer_size: int
) -> Tuple[bytes, List[int]]:
    """
    Receives data and any file descriptors passed along with it.

    Args:
        sock (socket): The non-blocking socket to read from
        buffer_size (int): Most bytes to read at once
    Returns:
        Tuple[bytes, List[int]]: The data (empty on EOF) and the received fds,
        which the caller must close
    """
    while True:
        try:
            data, fds, flags, _ = socket.recv_fds(sock, buffer_size, MAX_FDS)
        except (BlockingIOError, InterruptedError):
            await wait_ready(sock, writable=False)
            continue
        if flags & socket.MSG_CTRUNC:
            for fd in fds:
                os.close(fd)
            raise ConnectionError("Too many file descriptors in one message")
        return data, fds


async def send_with_fds(sock: socket.socket, data: bytes, fds: List[int]) -> None:
    """
    Sends all of data, passing fds along with its first byte.

    Args:
        sock (socket): The non-blocking socket to write to
        data (bytes): The data to send
        fds (List[int]): File descriptors to pass, still owned by the caller
    """
    ancillary = [(SOL_SOCKET, SCM_RIGHTS, array("i", fds))] if fds else []
    view = memoryview(data)
    while view:
        try:
            sent = sock.sendmsg([view], ancillary)
        except (BlockingIOError, InterruptedError):
            await wait_ready(sock, writable=True)
            continue
        view = view[sent:]
        ancillary = []


async def recv_exact(sock: socket.socket, size: int) -> Tuple[bytes, List[int]]:
    """
    Receives exactly size bytes (fewer on EOF) and any fds passed with them.

    Never reading past the requested size keeps fds tied to the D-Bus message
    they were sent with, since the kernel may otherwise merge the end of one
    message with the start of the next into a single read.

    Args:
        sock (socket): The socket to read from
        size (int): Number of bytes to read
    Returns:
        Tuple[bytes, List[int]]: The data and the received fds, which the
        caller must close
    """
    data, fds = b"", []
    try:
        while len(data) < size:
            chunk, chunk_fds = await recv_with_fds(sock, size - len(data))
            fds += chunk_fds
            if not chunk:
                break
            data += chunk
    except BaseException:
        # Also on cancellation, which happens when the other direction ends.
        for fd in fds:
            os.close(fd)
        raise
    return data, fds


async def read_line(sock: socket.socket) -> bytes:
    """
    Reads one auth line (up to and including "\\n", or until EOF).

    Reads byte by byte so nothing past the line is consumed.

    Args:
        sock (socket): The socket to read from
    Returns:
        bytes: The line
    """
    line = b""
    while not line.endswith(b"\n"):
        if len(line) >= MAX_AUTH_LINE:
            raise ConnectionError("Auth line too long")
        byte, fds = await recv_exact(sock, 1)
        for fd in fds:
            os.close(fd)
        if not byte:
            break
        line += byte
    return line


async def forward_auth(
    from_sock: socket.socket, to_sock: socket.socket, from_client: bool
) -> Optional[Tuple[bytes, List[int]]]:
    """
    Forwards auth lines until the binary message stream starts.

    The client's stream switches to messages after its BEGIN line. The bus
    sends no BEGIN, but its lines never start with a message's endianness
    byte ("l" or "B").

    Args:
        from_sock (socket): The socket to forward from
        to_sock (socket): The socket to forward to
        from_client (bool): Whether from_sock is the client
    Returns:
        Optional[Tuple[bytes, List[int]]]: Bytes of the first message already
        read and the fds passed with them, or None on EOF
    """
    while True:
        if from_client:
            line = await read_line(from_sock)
            if not line:
                return None
            await send_with_fds(to_sock, line, [])
            if line.split()[:1] == [b"BEGIN"]:
                return b"", []
        else:
            # Fds belong to the first byte of a message, so keep them here.
            first, fds = await recv_exact(from_sock, 1)
            if first in (b"l", b"B"):
                return first, fds
            for fd in fds:
                os.close(fd)
            if not first:
                return None
            await send_with_fds(to_sock, first + await read_line(from_sock), [])


async def forward(
    from_sock: socket.socket,
    to_sock: socket.socket,
    buffer_size: int,
    from_client: bool,
) -> None:
    """
    Forwards auth lines, then D-Bus messages one at a time with the fds
    passed along with each.

    Args:
        from_sock (socket): The socket to forward from
        to_sock (socket): The socket to forward to
        buffer_size (int): Size of the buffer to use
        from_client (bool): Whether from_sock is the client
    """
    started = await forward_auth(from_sock, to_sock, from_client)
    if started is None:
        return
    start, fds = started

    while True:
        try:
            header, more_fds = await recv_exact(from_sock, 16 - len(start))
            header, fds, start = start + header, fds + more_fds, b""
            if len(header) < 16:
                return
            order = {b"l": "<", b"B": ">"}.get(header[:1])
            if order is None:
                raise ConnectionError("Invalid D-Bus message")
            body_len, _, fields_len = struct.unpack_from(order + "3I", header, 4)
            # Header fields are padded to a multiple of 8 before the body.
            remaining = (fields_len + 7) // 8 * 8 + body_len
            await send_with_fds(to_sock, header, fds)
        finally:
            for fd in fds:
                os.close(fd)
            fds = []

        while remaining:
            data, data_fds = await recv_with_fds(
                from_sock, min(remaining, buffer_size)
            )
            try:
                if not data:
                    return
                await send_with_fds(to_sock, data, data_fds)
            finally:
                for fd in data_fds:
                    os.close(fd)
            remaining -= len(data)


async def handle_client(
    auth_data: bytes,
    client_sock: socket.socket,
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
        client_sock (socket): socket of the client connection
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    """
    logging.debug(f"Opening connection to system dbus at: {dbus_soc}")
    dbus_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dbus_sock.setblocking(False)
    await asyncio.get_running_loop().sock_connect(dbus_sock, dbus_soc)

    logging.debug("dbus connection established, fowarding AUTH message")
    await send_with_fds(dbus_sock, auth_data, [])

    dbus_to_client = asyncio.create_task(
        forward(dbus_sock, client_sock, buffer_size, from_client=False)
    )
    client_to_dbus = asyncio.create_task(
        forward(client_sock, dbus_sock, buffer_size, from_client=True)
    )

    logging.debug("Bi-directional stream established")
    done, pending = await asyncio.wait(
        {dbus_to_client, client_to_dbus}, return_when=asyncio.FIRST_COMPLETED
    )
    logging.debug("Bi-directional stream ended")
    for task in done:
        if task.exception():
            logging.debug(f"Forwarding ended: {task.exception()}")

    # Stop the other direction before its socket is closed under it.
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    dbus_sock.close()
    logging.debug("System dbus connection closed")


async def client_callback(
    sock: socket.socket, dbus_soc: str, buffer_size: int
) -> None:
    """
    Callback to handle a new client connection.

    Reads the initial auth message, transforms the UID, then blindly forwards
    data both ways after that.

    Args:
        sock (socket): socket of the client connection
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    """
    logging.debug("Accepted connection from client")
    socket_uid = get_socket_uid(sock)
    logging.debug(f"Client user id: {socket_uid}")
    if socket_uid is None:
        sock.close()
        return

    try:
        auth_data = await read_line(sock)
        auth_data = verify_and_transform(auth_data, socket_uid)

        logging.debug(f"Verification complete and UID fixed to {PROCESS_UID}")
        logging.debug("Will begin forwarding data")

        await handle_client(auth_data, sock, dbus_soc, buffer_size)
    except PermissionError as e:
        logging.warning(f"Permission Denied: {e}")
    except ConnectionError as e:
        logging.warning(f"Connection closed: {e}")
    finally:
        sock.close()


def gen_client_callback(
    dbus_soc: str, buffer_size: int
) -> Callable[[socket.socket], Awaitable[None]]:
    """
    Higher order function that generates a callback for the client connection
    acceptor.

    This function bascially bakes in context required to handle forwarding and
    returns a function that only takes in the client socket.

    Args:
        dbus_soc (str): path to the real dbus socket
        buffer_size (int): size of the buffer to use while forwarding to and
                           from the client
    Returns:
        Callable[[socket.socket], Awaitable[None]]:
            A callback suitable for the server acceptor
    """

    async def callback(sock: socket.socket) -> None:
        await client_callback(sock, dbus_soc, buffer_size)

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
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(opts.client_socket)
    server.listen()
    server.setblocking(False)

    logging.info(f"Proxy listening on {opts.client_socket}")
    logging.info(f"Forwarding to {opts.system_dbus}")

    loop = asyncio.get_running_loop()
    clients = set()
    while True:
        sock, _ = await loop.sock_accept(server)
        sock.setblocking(False)
        task = asyncio.create_task(handle_client(sock))
        clients.add(task)
        task.add_done_callback(clients.discard)


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
