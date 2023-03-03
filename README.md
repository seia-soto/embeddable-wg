# Embeddable-WG bindings for Node.JS

[![Release](https://github.com/seia-soto/embeddable-wg/actions/workflows/build.yml/badge.svg)](https://github.com/seia-soto/embeddable-wg/actions/workflows/build.yml)

This library includes bindings of the embeddable-wg-library, allowing for efficient calls to set up WireGuard devices.

See [Official WireGuard website](https://wireguard.com) and [wireguard-tools/contrib/embeddable-wg-library](https://git.zx2c4.com/wireguard-tools/tree/contrib/embeddable-wg-library) for more information.

We support **glibc- and musl-libc-based x86_64 and aarch64 systems on Linux** and control the network interface via `ioctl`.
We provide the [direct bindings](#bindings) to embeddable-wg-library and [class wrappers](#class-wrappers) on it for easy use.

## Errors

The expected errors are defined in [constants.h](adaptor/constants.h).

```c
#define EWB_AF_UNSPEC "EWB_AF_UNSPEC"       // If the ip address format is not valid ipv4 or ipv6.
#define EWB_AI_UNFORMAT "EWB_AI_UNFORMAT"   // If the value is not in valid format: for example, peer->endpoint takes `ip:port` schema.
#define EWB_OBJ_UNSPEC "EWB_OBJ_UNSPEC"     // If we failed to unwrap napi_value object into wireguard structs.
#define EWB_ARG_UNSPEC "EWB_ARG_UNSPEC"     // If the argument given is not valid.
#define EWB_LIB_CALLFAIL "EWB_LIB_CALLFAIL" // If we failed to call wireguard library functions.
#define EWB_NNA_CALLFAIL "EWB_NNA_CALLFAIL" // If we failed to call napi library functions.
#define EWB_SOC_CALLFAIL "EWB_SOC_CALLFAIL" // If we failed to call socket to kernel or related system calls.
```

## Bindings

You can import the binding object via `import {wg} from 'embeddable-wg';`.
For modification of the device and interface, refer to [Applying modifications](#applying-modifications) for instructions on performing automatic bitwise operations.

```typescript
export type AddressFamily = Binding['AF_INET'] | Binding['AF_INET6'];

export type InterfaceAddress = {
	family: AddressFamily;
	ip: string;
};

export type WireguardAllowedIp = {
	addr: string;
	family: AddressFamily;
	cidr: number;
};

export type WireguardPeer = {
	flags: number;
	publicKey: string;
	presharedKey: string;
	endpoint: string;
	persistentKeepaliveInterval: number;
	allowedIps: WireguardAllowedIp[];
};

export type WireguardDevice = {
	name: string;
	ifindex: number;
	flags: number;
	publicKey: string;
	privateKey: string;
	fwmark: number;
	listenPort: number;
	peers: WireguardPeer[];
};

export type Binding = {
	getDevice: (deviceName: string) => WireguardDevice;
	setDevice: (device: WireguardDevice) => void;
	addDevice: (deviceName: string) => void;
	removeDevice: (deviceName: string) => void;
	listDeviceNames: () => string[];
	generatePublicKey: (privateKey: string) => string;
	generatePrivateKey: () => string;
	generatePresharedKey: () => string;
	getInterfaceAddress: (deviceName: string) => InterfaceAddress[];
	setInterfaceAddress: (deviceName: string, address: InterfaceAddress) => void;
	WGDEVICE_REPLACE_PEERS: number;
	WGDEVICE_HAS_PRIVATE_KEY: number;
	WGDEVICE_HAS_PUBLIC_KEY: number;
	WGDEVICE_HAS_LISTEN_PORT: number;
	WGDEVICE_HAS_FWMARK: number;
	WGPEER_REMOVE_ME: number;
	WGPEER_REPLACE_ALLOWEDIPS: number;
	WGPEER_HAS_PUBLIC_KEY: number;
	WGPEER_HAS_PRESHARED_KEY: number;
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL: number;
	AF_INET: number;
	AF_INET6: number;
};
```

### Applying modifications

If you plan to modify a device or peer, it is important to set the proper flags property before applying any modifications.
For example, if you want to apply changes to the `publicKey` property of an object retrieved from the `wg.getDevice` method, you will need to set the `WGDEVICE_HAS_PUBLIC_KEY` flag.
Setting flags is same as it uses a simple bitwise system.

```typescript
import {wg} from 'embeddable-wg';

const dev = wg.getDevice('wgtest0');

dev.privateKey = wg.generatePrivateKey();
dev.publicKey = wg.generatePublicKey(dev.privateKey);

dev.flags |= wg.WGDEVICE_HAS_PRIVATE_KEY;
dev.flags |= wg.WGDEVICE_HAS_PUBLIC_KEY;
```

While the class wrapper automates this process, it is also safe to use the binding directly if you need to implement a more efficient method.

### Address families and IP format

The address family describes the type of IP address that will be used.
We provide `AF_INET` and `AF_INET6` from the binding source instead of hard-coding the values.
Each of these constants refers to IPv4 and IPv6, respectively.

```typescript
import {wg} from 'embeddable-wg'

const ia = {
    "ip": "10.0.0.1",
    "family": wg.AF_INET,
}
```

## Class wrappers

We also provide class wrappers for easy use.
The main purpose of these class wrappers is to operate on the flags property automatically when a matching method is called.

```typescript
import { type Binding, type WireguardAllowedIp, type WireguardPeer, type WireguardDevice, type AddressFamily } from '../types/wg.js';
export declare const wg: Binding;
export type { WireguardAllowedIp, WireguardPeer, WireguardDevice, };
export declare class WgPeer {
    flags: number;
    publicKey: string;
    presharedKey: string;
    endpoint: string;
    persistentKeepaliveInterval: number;
    allowedIps: WireguardAllowedIp[];
    private readonly device;
    constructor(device: WgDevice, peer: WireguardPeer);
    /**
     * Sets allowed ips for the peer.
     * Note that this method completely replaces allowedIps value for the peer.
     * @example peer.setAllowedIps([{family: wg.AF_INET, addr: '10.0.0.2', cidr: 32}]);
     * @param allowedIps The array of allowed ips.
     * @returns Returns `this`.
     */
    setAllowedIps(allowedIps: WireguardAllowedIp[]): this;
    /**
     * Sets public key for the peer.
     * You can generate the key via `wg.generatePublicKey(peer.presharedKey);`.
     * @example peer.setPublicKey(wg.generatePublicKey(peer.presharedKey));
     * @param key The public key in base64 format.
     * @returns Returns `this`.
     */
    setPublicKey(key: string): this;
    /**
     * Sets preshared key for the peer.
     * You can generate the key via `wg.generatePresharedKey();`.
     * @example peer.setPresharedKey(wg.generatePresharedKey());
     * @param key The preshared key in base64 format.
     * @returns Returns `this`.
     */
    setPresharedKey(key: string): this;
    /**
     * Removes the peer from the device.
     */
    remove(): void;
    private update;
}
export declare class WgDevice {
    name: string;
    ifindex: number;
    flags: number;
    publicKey: string;
    privateKey: string;
    fwmark: number;
    listenPort: number;
    peers: WgPeer[];
    constructor(device: WireguardDevice);
    /**
     * Gets the interface address of the device interface.
     * @returns The array of interface addresses.
     */
    getInterfaceAddress(): import("../types/wg.js").InterfaceAddress[];
    /**
     * Sets the interface address of the device interface.
     * @example device.setInterfaceAddress(wg.AF_INET, '10.0.0.1');
     * @param family The address family; should be wg.AF_INET or wg.AF_INET6.
     * @param ip The ip address without any additional information; such as protocol.
     * @returns Returns `this`.
     */
    setInterfaceAddress(family: AddressFamily, ip: string): this;
    /**
     * Sets the public key for the device.
     * @example device.setPublicKey(wg.generatePrivateKey(device.publicKey));
     * @param key The public key in base64 format.
     * @returns Returns `this`.
     */
    setPublicKey(key: string): this;
    /**
     * Sets the private key for the device.
     * @example device.setPrivateKey(wg.generatePrivateKey());
     * @param key The private key in base64 format.
     * @returns Returns `this`.
     */
    setPrivateKey(key: string): this;
    /**
     * Sets the `fwmark` for the device.
     * WARNING; `fwmark` is used to route the packet to specific interface in Linux netfilter, and can lead to unexpected result.
     * @param fwmark The fwmark value.
     * @returns Returns `this`.
     */
    setFwmark(fwmark: number): this;
    /**
     * Sets the port number for the device.
     * @example device.setListenPort(8888);
     * @param port The port number.
     * @returns Returns `this`.
     */
    setListenPort(port: number): this;
    /**
     * Adds a peer to the device.
     * @param source The peer source.
     * @returns Returns `this`.
     */
    addPeer(source: WireguardPeer): this;
    /**
     * Removes the device.
     */
    remove(): void;
    private update;
}
//# sourceMappingURL=index.d.ts.map
```

### Initialization

To initialize the class wrappers, you'll simply need to retrieve the `WireguardDevice` and `WireguardPeer` object from native binding.

```typescript
import {wg, WgDevice} from 'embeddable-wg';

const dev = new WgDevice(wg.getDevice(targetDevName));
```

Once initialized, the flags property will be handled automatically when using methods from the class wrapper.
