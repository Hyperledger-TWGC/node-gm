/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const sm3 = require('./sm_sm3');

function signRS(sm2KeyPair, msg) {
	const x = sm2KeyPair.pub.getX().toString(16);
	const y = sm2KeyPair.pub.getY().toString(16);
	let pubKeyHex = x + y;
	if (pubKeyHex.length !== 128) {
		pubKeyHex = pubKeyHex.padStart(128, '0');
	}
	const _msg = Array.from(msg);

	const signData = sm2KeyPair.sign(_msg);
	let rHex = '000000000000000000000' + signData.r;
	let sHex = '000000000000000000000' + signData.s;
	const rHexLen = rHex.length - 64;
	const sHexLen = sHex.length - 64;
	rHex = rHex.substr(rHexLen, 64);
	sHex = sHex.substr(sHexLen, 64);

	const r = Buffer.from(rHex, 'hex');
	const s = Buffer.from(sHex, 'hex');
	const pub = Buffer.from(pubKeyHex, 'hex');
	return {'r': r, 's': s, 'pub': pub};
}

function priToPub(sm2KeyPair) {
	const x = sm2KeyPair.pub.getX().toString(16);
	const y = sm2KeyPair.pub.getY().toString(16);

	let pubKeyHex = x + y;
	if (pubKeyHex.length !== 128) {
		pubKeyHex = pubKeyHex.padStart(128, '0');
	}
	return Buffer.from(pubKeyHex, 'hex');
}

function sm3Digest(msg) {
	const _sm3 = new sm3();
	const rawData = Array.from(msg);
	const digest = _sm3.sum(rawData);
	return Array.from(digest, (byte) => {
		return ('0' + (byte & 0xFF).toString(16)).slice(-2);
	}).join('');
}

module.exports = {
	sm3Digest,
	signRS,
	priToPub
};
