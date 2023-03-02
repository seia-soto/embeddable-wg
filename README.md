# Embeddable-WG bindings for Node.JS

[![Release](https://github.com/seia-soto/embeddable-wg/actions/workflows/build.yml/badge.svg)](https://github.com/seia-soto/embeddable-wg/actions/workflows/build.yml)

This package includes bindings of embeddable-wg-library in wireguard-tools library for efficient calls to set up WireGuard devices.

## Notes

- This module requires you to be on Linux to be compiled.
- This module is not production-ready as there can be some memory-leak issues.
- This module is written in ESM format and I will no support or convert it into CJS format.

## Usage

Please, use class wrappers for easy use.

### Bindings

You can import the binding object via `import {wg} from 'embeddable-wg';`.

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

#### Applying modifications

If you're going to modify the device or peer, you should set proper flags property before applying any of modifications.
For example, you'll need to set `WGDEVICE_HAS_PUBLIC_KEY` if you want to apply changes on object got from `wg.getDevice` method.

The way to set flag is easy as it's just simple bitwise system.

```typescript
import {wg} from 'embeddable-wg';

const dev = wg.getDevice('wgtest0');

dev.privateKey = wg.generatePrivateKey();
dev.publicKey = wg.generatePublicKey(dev.privateKey);

dev.flags |= wg.WGDEVICE_HAS_PRIVATE_KEY;
dev.flags |= wg.WGDEVICE_HAS_PUBLIC_KEY;
```

The class wrapper automates this.
However, it's safe to use binding directly if you want to implement more efficient method.

#### Address families and IP format

The address family describes what type of the IP address you'll use.
We provide `AF_INET` and `AF_INET6` from the binding source instead of hard-coding the values.
Each of them refers IPv4 and IPv6.

```typescript
import {wg} from 'embeddable-wg'

const ia = {
    "ip": "10.0.0.1",
    "family": wg.AF_INET,
}
```

### Class wrappers

We also provide class wrappers for easy use.

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
    setAllowedIps(allowedIps: WireguardAllowedIp[]): this;
    setPublicKey(key: string): this;
    setPresharedKey(key: string): this;
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
    getInterfaceAddress(): import("../types/wg.js").InterfaceAddress[];
    setInterfaceAddress(family: AddressFamily, ip: string): this;
    setPublicKey(key: string): this;
    setPrivateKey(key: string): this;
    setFwmark(fwmark: number): this;
    setListenPort(port: number): this;
    addPeer(source: WireguardPeer): this;
    remove(): void;
    private update;
}
//# sourceMappingURL=index.d.ts.map
```

#### Initialization

To initialize the class wrappers, you'll simply need to get the `WireguardDevice` and `WireguardPeer` object from native binding.

```typescript
import {wg, WgDevice} from 'embeddable-wg';

const dev = new WgDevice(wg.getDevice(targetDevName));
```

After the initialization, the flags property will be handled automatically while using methods from the class wrapper.
