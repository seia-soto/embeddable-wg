# Embeddable-WG bindings for Node.JS

This package includes bindings of embeddable-wg-library in wireguard-tools library for efficient calls to set up WireGuard devices.

## Notes

- This module requires you to be on Linux to be compiled.
- This module is not production-ready as there can be some memory-leak issues.
- This module is written in ESM format and I will no support or convert it into CJS format.

## Usage

### Bindings

You can import the binding object via `import {wg} from 'embeddable-wg';`.

See [binding definition](/types/wg.d.ts) for full usage.

### Class wrappers

We also provide class wrappers for easy use.

See [example.js](/example.js) for example usage.

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