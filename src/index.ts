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

	setAllowedIps(allowedIps: WireguardAllowedIp[]) {
		this.flags |= wg.WGPEER_REPLACE_ALLOWEDIPS;
		this.allowedIps = allowedIps;

		this.update();

		return this;
	}

	setPublicKey(key: string) {
		this.flags |= wg.WGPEER_HAS_PUBLIC_KEY;
		this.publicKey = key;

		this.update();

		return this;
	}

	setPresharedKey(key: string) {
		this.flags |= wg.WGPEER_HAS_PRESHARED_KEY;
		this.presharedKey = key;

		this.update();

		return this;
	}

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

	getInterfaceAddress() {
		return wg.getInterfaceAddress(this.name);
	}

	setInterfaceAddress(family: AddressFamily, ip: string) {
		wg.setInterfaceAddress(this.name, {family, ip});

		return this;
	}

	setPublicKey(key: string) {
		this.flags |= wg.WGDEVICE_HAS_PUBLIC_KEY;
		this.publicKey = key;

		this.update();

		return this;
	}

	setPrivateKey(key: string) {
		this.flags |= wg.WGDEVICE_HAS_PRIVATE_KEY;
		this.privateKey = key;

		this.update();

		return this;
	}

	setFwmark(fwmark: number) {
		this.flags |= wg.WGDEVICE_HAS_FWMARK;
		this.fwmark = fwmark;

		this.update();

		return this;
	}

	setListenPort(port: number) {
		this.flags |= wg.WGDEVICE_HAS_LISTEN_PORT;
		this.listenPort = port;

		this.update();

		return this;
	}

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
