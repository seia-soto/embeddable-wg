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
