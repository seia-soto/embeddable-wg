import {wg, WgDevice} from './out/index.js';

const targetDevName = 'wgtest0';

(async () => {
	if (wg.listDeviceNames().includes(targetDevName)) {
		wg.removeDevice(targetDevName);
	}

	wg.addDevice(targetDevName);

	const dev = new WgDevice(wg.getDevice(targetDevName));
	const psk = wg.generatePresharedKey();

	dev
		.setInterfaceAddress(wg.AF_INET, '10.0.0.1')
		.setListenPort(1234)
		.setPrivateKey(wg.generatePrivateKey())
		.addPeer({
			allowedIps: [
				{
					addr: '10.0.0.2/32',
					family: wg.AF_INET,
					cidr: 32,
				},
			],
			endpoint: '192.168.0.1:8080',
			flags: 0,
			persistentKeepaliveInterval: 30,
			presharedKey: psk,
			publicKey: wg.generatePublicKey(psk),
		});

	console.log(wg.getDevice(targetDevName));
	console.log(wg.getInterfaceAddress(targetDevName));
})();
