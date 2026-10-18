# dbus-auth-proxy

dbus-auth-proxy is a proxy that overrides the user id in the [AUTH EXTERNAL](https://dbus.freedesktop.org/doc/dbus-specification.html#auth-mechanisms-external) message of a dbus request. The proxy is intended to be used in containers running in rootless mode (e.g. podman rootless containers) to access the system dbus when the application's dbus client sets a UID in AUTH EXTERNAL.

It produces a unix socket that mimics the system dbus unix socket. This socket should then be mounted in the rootless container in question at `/run/dbus/system_bus_socket` so that dbus requests flow through the proxy and their AUTH EXTERNAL message will be fixed.

## The Issue

If you ever run podman in rootless mode, you might notice having trouble with dbus on some clients. For example, as for writing, this will fail with an auth error:

```bash
podman run -it --rm -v /run/dbus:/run/dbus:rw --security-opt label=disable alpine
apk add dbus
dbus-send --system --print-reply --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect
```

A more practical example: if you run [Home Assistant](https://www.home-assistant.io/) in a rootless podman, you'll most likely have trouble with bluetooth:

> DBus authentication error; make sure the DBus socket is available and the user has the correct permissions: authentication failed: REJECTED: ['EXTERNAL']

This has been reported in a number of places:

- [Blog Post](https://blog.troed.se/posts/bluetooth-and-home-assistant-in-rootless-docker/)
  - [Corresponding Forum Link](https://community.home-assistant.io/t/bluetooth-and-docker-part-2/447334/9?u=troed)
    - Suggests a monkey patch to remove UID from the AUTH sequence
- [Home Assistant Github Issue](https://github.com/home-assistant/core/issues/76429)
- [Another forum post](https://community.home-assistant.io/t/bluetooth-dbus-authentication-error/803831)

## Original vs. this fork

This is a fork of [yichenshen/dbus-auth-proxy](https://github.com/yichenshen/dbus-auth-proxy). Either works for basic D-Bus access:

- **Original**: pulls the published image `ghcr.io/yichenshen/dbus-auth-proxy:latest` and auto-updates from the registry. Follow the [upstream README](https://github.com/yichenshen/dbus-auth-proxy#running).
- **This fork**: builds the image locally from your checkout via quadlet (no registry image, no auto-update) and forwards file descriptors passed over D-Bus. The original drops them, so fd-returning calls such as BlueZ `AcquireWrite`/`AcquireNotify` (used by Home Assistant's Bluetooth stack via bleak) fail or hang, depending on the client. It also exits cleanly on SIGTERM. Instructions below.

## Running

If you're not interested in the details, you can simply run this proxy in a container alongside the container you want dbus for. The image is built locally from this checkout (nothing is pulled from a registry other than the `python:slim` base image).

Requires podman 5.2+ (first release with quadlet `.build` units). From a clone of this repo:

```
./quadlet/install.sh
systemctl --user start dbus-auth-proxy
```

`install.sh` copies `quadlet/dbus-auth-proxy.container` and renders `quadlet/dbus-auth-proxy.build.in` (with this checkout's absolute path) into `~/.config/containers/systemd/`. Starting the service builds `localhost/dbus-auth-proxy:latest` via the `dbus-auth-proxy-build` unit, then runs it. To start on boot without logging in, enable lingering: `loginctl enable-linger $USER`.

To update after pulling new code, restart the build unit along with the service so the image is rebuilt from the checkout (podman's layer cache keeps this fast):

```
git pull
systemctl --user restart dbus-auth-proxy-build dbus-auth-proxy
```

If you move the checkout, re-run `./quadlet/install.sh`.

This will create a named volume called `dbus-socket`, and the container will register a `system_bus_socket` into this volume. You then simply mount this volume in place of `/run/dbus/` on the container you want dbus for.

```bash
podman run -it --rm -v dbus-socket:/run/dbus:rw --security-opt label=disable alpine
apk add dbus
dbus-send --system --print-reply --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect
```

This should now work and list you the dbus endpoints. Run the proxy and the client containers as the same user, and mount the volume (not the socket file) so clients see the new socket after the proxy restarts.

For Home Assistant, use `Volume=dbus-socket:/run/dbus:rw` instead of the usual `/run/dbus:/run/dbus:ro`. This avoids `--userns=keep-id` on the Home Assistant container, which combined with rootless overlay/vfs storage can make it very slow.

### Optional: filter with xdg-dbus-proxy

To limit the container to BlueZ instead of everything your user can reach on the system bus, chain [xdg-dbus-proxy](https://github.com/flatpak/xdg-dbus-proxy) behind the proxy. Install it on the host (e.g. `apt install xdg-dbus-proxy`), copy `quadlet/dbus-filter.service` to `~/.config/systemd/user/` and `quadlet/dbus-auth-proxy.container.d/filter.conf` to `~/.config/containers/systemd/dbus-auth-proxy.container.d/`, then run `systemctl --user daemon-reload` and restart `dbus-auth-proxy`. Add a `--talk=` rule in `dbus-filter.service` for each other service the container needs, then `systemctl --user daemon-reload` and restart `dbus-filter`.

## Details: Dbus Authentication

Note that this is **not** a dbus permission policy problem. It actually lies with how user ids are changed across container=>host and how that interacts with the AUTH EXTERNAL mechanism of dbus.

### AUTH EXTERNAL

When connecting to dbus, there are a number of authentication mechanisms. For a local connection via unix sockets (to `/run/dbus/system_bus_socket`), it's usually simplest to use AUTH EXTERNAL. This means it relies on an external verifier, in this case the kernel, to verify which user is connecting. Here, a unix socket connection has a `SO_PEERCRED` option that tells you the user id of the connecting client. AUTH EXTERNAL basically uses that to detemine the user that's connecting and apply
permission policies.

AUTH EXTERNAL has an extra optional mechanism. You can also supply a user id in the auth sequence itself. If you do so, then dbus will check this against then sockets user id, and only if they match, continue with the rest of the interaction. This isn't strictly neccessary, since the kernel already verified the user id, but you can specify it anyway for an additional check.

The above issue is usually when the supplied user id does not match the socket user id. Not supplying the user id in the dbus library is what the blog post above is trying to patch to fix the problem.

### Container User ID

But why doesn't the user id match? This has to do with podman rootless containers. In a rootless container, the process inside the container runs as `root` by default (uid: 0). The container itself however runs as a non-root user, like uid: 1000. When socket connections are made from the container to the host, the uid is translated from the container namespace to the host namespace. This means that if you open a connection from a container to the dbus socket, inside the container you'll see the
sockets uid to be 0. Outside the container it'll appear as 1000. When dbus does AUTH EXTERNAL, it'll thus see this socket as coming from your non-root user, uid: 1000, and will only confer it permissions for that user. This is expected and desired.

The trouble starts with clients in the container opting to use the additional user id check. In the container if the client decides to write it's own user id, it'll write uid: 0 into the AUTH EXTERNAL sequence. This is just data through the connection, and so when it crosses the container/host boundary it won't be transformed unlike the underlying socket metadata (podman won't know this is supposed to be a user id to begin with). Thus, when it arrives at dbus, it have receives AUTH EXTERNAL for uid: 0 but the socket's user id is 1000. It will reject the connection due to a mismatch.

The github issue above fixes this with `--userns=keep-id`. This runs the container process under uid: 1000, and thus avoids the problem because the client inside will now use 1000 for AUTH EXTERNAL. For some containers though, this creates another problem. Because the process in the container is now not running under `root` (uid: 0), it has less permissions **inside** the container. For Home Assistant for example, HACS will need root permissions for `pip install`, and running with
`--userns=keep-id` will cause it to fail.

## Proxying and Transforming

The pupose of the `dbus-auth-proxy` is to have an non-invasive way to get around this without having to patch the client or force it to run without root in the container.

It addresses the problem by intercepting the AUTH EXTERNAL message and fixing the user id. Essentially, `dbus-auth-proxy` creates it's own unix socket that mimics `/run/dbus/system_bus_socket`. When it receives an AUTH EXTERNAL message, it'll verify that the connection's user id is the same as it's own (meaning that dbus-auth-proxy is not granting the client any new credentials it doesn't already have). Then it fixes the AUTH EXTERNAL message's user id if supplied to it's own user id.

Then, what we do this to run `dbus-auth-proxy` in a container with `--userns=keep-id`. Afterwards, we mount the proxy socket it produces as the system dbus socket into the target container. This way, when the target container's dbus client connects with AUTH EXTERNAL, `dbus-auth-proxy` will get the message instead and fix the user id to it's own user id, which is the right one (because it runs with `--userns=keep-id`). Then it just forwards the rest of the data bi-directionally.

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (MIT).
