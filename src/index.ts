import bin from '@mapbox/node-pre-gyp';
import path from 'path';
import {type Binding, type WireguardAllowedIp, type WireguardPeer, type WireguardDevice, type AddressFamily} from '../types/wg.js';
import {createRequire} from 'module';

const bindingPath = bin.find(path.resolve(path.join(import.meta.url.split('://')[1], '../../package.json')));
const require = createRequire(import.meta.url);

export const wg = require(bindingPath) as Binding;

export type {
	WireguardAllowedIp,
	WireguardPeer,
	WireguardDevice,
};

export class WgPeer {
	flags: number;
	publicKey: string;
	presharedKey: string;
	endpoint: string;
	persistentKeepaliveInterval: number;
	allowedIps: WireguardAllowedIp[];

	private readonly device: WgDevice;

	constructor(device: WgDevice, peer: WireguardPeer) {
		this.flags = 0;
		this.publicKey = peer.publicKey;
		this.presharedKey = peer.presharedKey;
		this.endpoint = peer.endpoint;
		this.persistentKeepaliveInterval = peer.persistentKeepaliveInterval;
		this.allowedIps = peer.allowedIps;

		this.device = device;
	}

	/**
	 * Sets allowed ips for the peer.
	 * Note that this method completely replaces allowedIps value for the peer.
	 * @example peer.setAllowedIps([{family: wg.AF_INET, addr: '10.0.0.2', cidr: 32}]);
	 * @param allowedIps The array of allowed ips.
	 * @returns Returns `this`.
	 */
	setAllowedIps(allowedIps: WireguardAllowedIp[]) {
		this.flags |= wg.WGPEER_REPLACE_ALLOWEDIPS;
		this.allowedIps = allowedIps;

		this.update();

		return this;
	}

	/**
	 * Sets public key for the peer.
	 * You can generate the key via `wg.generatePublicKey(peer.presharedKey);`.
	 * @example peer.setPublicKey(wg.generatePublicKey(peer.presharedKey));
	 * @param key The public key in base64 format.
	 * @returns Returns `this`.
	 */
	setPublicKey(key: string) {
		this.flags |= wg.WGPEER_HAS_PUBLIC_KEY;
		this.publicKey = key;

		this.update();

		return this;
	}

	/**
	 * Sets preshared key for the peer.
	 * You can generate the key via `wg.generatePresharedKey();`.
	 * @example peer.setPresharedKey(wg.generatePresharedKey());
	 * @param key The preshared key in base64 format.
	 * @returns Returns `this`.
	 */
	setPresharedKey(key: string) {
		this.flags |= wg.WGPEER_HAS_PRESHARED_KEY;
		this.presharedKey = key;

		this.update();

		return this;
	}

	/**
	 * Removes the peer from the device.
	 */
	remove() {
		this.flags |= wg.WGPEER_REMOVE_ME;
		this.device.peers = this.device.peers.filter(peer => peer !== this);

		this.update();
	}

	private update() {
		wg.setDevice({
			...this.device,
			peers: [this],
		});
	}
}

export class WgDevice {
	name: string;
	ifindex: number;
	flags: number;
	publicKey: string;
	privateKey: string;
	fwmark: number;
	listenPort: number;

	peers: WgPeer[] = [];

	constructor(device: WireguardDevice) {
		this.name = device.name;
		this.ifindex = device.ifindex;
		this.flags = 0;
		this.publicKey = device.publicKey;
		this.privateKey = device.privateKey;
		this.fwmark = device.fwmark;
		this.listenPort = device.listenPort;
		this.peers = device.peers.map(peer => new WgPeer(this, peer));
	}

	/**
	 * Gets the interface address of the device interface.
	 * @returns The array of interface addresses.
	 */
	getInterfaceAddress() {
		return wg.getInterfaceAddress(this.name);
	}

	/**
	 * Sets the interface address of the device interface.
	 * @example device.setInterfaceAddress(wg.AF_INET, '10.0.0.1');
	 * @param family The address family; should be wg.AF_INET or wg.AF_INET6.
	 * @param ip The ip address without any additional information; such as protocol.
	 * @returns Returns `this`.
	 */
	setInterfaceAddress(family: AddressFamily, ip: string) {
		wg.setInterfaceAddress(this.name, {family, ip});

		return this;
	}

	/**
	 * Sets the public key for the device.
	 * @example device.setPublicKey(wg.generatePrivateKey(device.publicKey));
	 * @param key The public key in base64 format.
	 * @returns Returns `this`.
	 */
	setPublicKey(key: string) {
		this.flags |= wg.WGDEVICE_HAS_PUBLIC_KEY;
		this.publicKey = key;

		this.update();

		return this;
	}

	/**
	 * Sets the private key for the device.
	 * @example device.setPrivateKey(wg.generatePrivateKey());
	 * @param key The private key in base64 format.
	 * @returns Returns `this`.
	 */
	setPrivateKey(key: string) {
		this.flags |= wg.WGDEVICE_HAS_PRIVATE_KEY;
		this.privateKey = key;

		this.update();

		return this;
	}

	/**
	 * Sets the `fwmark` for the device.
	 * WARNING; `fwmark` is used to route the packet to specific interface in Linux netfilter, and can lead to unexpected result.
	 * @param fwmark The fwmark value.
	 * @returns Returns `this`.
	 */
	setFwmark(fwmark: number) {
		this.flags |= wg.WGDEVICE_HAS_FWMARK;
		this.fwmark = fwmark;

		this.update();

		return this;
	}

	/**
	 * Sets the port number for the device.
	 * @example device.setListenPort(8888);
	 * @param port The port number.
	 * @returns Returns `this`.
	 */
	setListenPort(port: number) {
		this.flags |= wg.WGDEVICE_HAS_LISTEN_PORT;
		this.listenPort = port;

		this.update();

		return this;
	}

	/**
	 * Adds a peer to the device.
	 * @param source The peer source.
	 * @returns Returns `this`.
	 */
	addPeer(source: WireguardPeer) {
		const peer = new WgPeer(this, source);

		peer.flags = wg.WGPEER_REPLACE_ALLOWEDIPS | wg.WGPEER_HAS_PUBLIC_KEY | wg.WGPEER_HAS_PRESHARED_KEY;

		wg.setDevice({
			...this,
			peers: [peer],
		});
		this.peers.push(peer);

		return this;
	}

	/**
	 * Removes the device.
	 */
	remove() {
		wg.removeDevice(this.name);
	}

	private update() {
		wg.setDevice({
			...this,
			peers: [],
		});
	}
}
