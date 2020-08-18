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

const utils = require('./sm_utils');

/**
 * SM3 Hash algorithm
 */
class SM3 {
	constructor() {
		this.reg = new Array(8);
		this.chunk = [];
		this.size = 0;

		this.reset();
	}

	reset() {
		this.reg[0] = 0x7380166f;
		this.reg[1] = 0x4914b2b9;
		this.reg[2] = 0x172442d7;
		this.reg[3] = 0xda8a0600;
		this.reg[4] = 0xa96f30bc;
		this.reg[5] = 0x163138aa;
		this.reg[6] = 0xe38dee4d;
		this.reg[7] = 0xb0fb0e4e;
		this.chunk = [];
		this.size = 0;
	}

	/**
	 * Stream hashing method
	 * Calling sum() to get hash of the whole data written in.
	 */
	write(msg) {
		const m = (typeof msg === 'string') ? utils.strToBytes(msg) : msg;
		this.size += m.length;
		let i = 64 - this.chunk.length;
		if (m.length < i) {
			this.chunk = this.chunk.concat(m);
			return;
		}

		this.chunk = this.chunk.concat(m.slice(0, i));
		while (this.chunk.length >= 64) {
			this._compress(this.chunk);
			if (i < m.length) {
				this.chunk = m.slice(i, Math.min(i + 64, m.length));
			} else {
				this.chunk = [];
			}
			i += 64;
		}
	}

	/**
	 * Get the 256-bit digest
	 *
	 * If @msg is not null, the digest is for @msg,
	 * else the digest is for previous inputs with write().
	 *
	 * The output could be a byte array, or a hex string with @enc set to 'hex'
	 *
	 * After calling sum(), the hash algo will reset to the initial state.
	 */
	sum(msg, enc) {
		if (msg) {
			this.reset();
			this.write(msg);
		}

		this._fill();
		for (let i = 0; i < this.chunk.length; i += 64) {
			this._compress(this.chunk.slice(i, i + 64));
		}
		let digest = '';
		if (enc === 'hex') {
			for (let i = 0; i < 8; i++) {
				digest += this.reg[i].toString(16);
			}
		} else {
			digest = new Array(32);
			for (let i = 0; i < 8; i++) {
				let h = this.reg[i];
				digest[i * 4 + 3] = (h & 0xff) >>> 0;
				h >>>= 8;
				digest[i * 4 + 2] = (h & 0xff) >>> 0;
				h >>>= 8;
				digest[i * 4 + 1] = (h & 0xff) >>> 0;
				h >>>= 8;
				digest[i * 4] = (h & 0xff) >>> 0;
			}
		}

		this.reset();
		return digest;
	}

	_compress(m) {
		if (m < 64) {
			throw new Error('compress error: not enough data');
		}


		const _t = (j) => {
			if (j >= 0 && j < 16) {
				return 0x79cc4519;
			} else if (j >= 16 && j < 64) {
				return 0x7a879d8a;
			} else {
				throw Error('invalid j for constant Tj');
			}
		};
		const _rotl = (x, n) => {
			n %= 32;
			return ((x << n) | (x >>> (32 - n))) >>> 0;
		};
		const _expand = (b) => {
			const w = new Array(132);
			for (let i = 0; i < 16; i++) {
				w[i] = b[i * 4] << 24;
				w[i] |= b[i * 4 + 1] << 16;
				w[i] |= b[i * 4 + 2] << 8;
				w[i] |= b[i * 4 + 3];
				w[i] >>>= 0;
			}

			let x;
			for (let j = 16; j < 68; j++) {
				x = w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15);
				x = x ^ _rotl(x, 15) ^ _rotl(x, 23);
				w[j] = (x ^ _rotl(w[j - 13], 7) ^ w[j - 6]) >>> 0;
			}

			for (let j = 0; j < 64; j++) {
				w[j + 68] = (w[j] ^ w[j + 4]) >>> 0;
			}

			return w;
		};

		const _ff = (j, x, y, z) => {
			if (j >= 0 && j < 16) {
				return (x ^ y ^ z) >>> 0;
			} else if (j >= 16 && j < 64) {
				return ((x & y) | (x & z) | (y & z)) >>> 0;
			} else {
				throw Error('invalid j for bool function FF');
			}
		};
		const _gg = (j, x, y, z) => {
			if (j >= 0 && j < 16) {
				return (x ^ y ^ z) >>> 0;
			} else if (j >= 16 && j < 64) {
				return ((x & y) | (~x & z)) >>> 0;
			} else {
				throw Error('invalid j for bool function GG');
			}
		};
		const w = _expand(m);
		const r = this.reg.slice(0);
		for (let j = 0; j < 64; j++) {
			let ss1 = _rotl(r[0], 12) + r[4] + _rotl(_t(j), j);
			ss1 = (ss1 & 0xffffffff) >>> 0;
			ss1 = _rotl(ss1, 7);

			const ss2 = (ss1 ^ _rotl(r[0], 12)) >>> 0;

			let tt1 = _ff(j, r[0], r[1], r[2]);
			tt1 = tt1 + r[3] + ss2 + w[j + 68];
			tt1 = (tt1 & 0xffffffff) >>> 0;

			let tt2 = _gg(j, r[4], r[5], r[6]);
			tt2 = tt2 + r[7] + ss1 + w[j];
			tt2 = (tt2 & 0xffffffff) >>> 0;

			r[3] = r[2];
			r[2] = _rotl(r[1], 9);
			r[1] = r[0];
			r[0] = tt1;
			r[7] = r[6];
			r[6] = _rotl(r[5], 19);
			r[5] = r[4];
			r[4] = (tt2 ^ _rotl(tt2, 9) ^ _rotl(tt2, 17)) >>> 0;
		}

		for (let i = 0; i < 8; i++) {
			this.reg[i] = (this.reg[i] ^ r[i]) >>> 0;
		}
	}

	// fill chunk to length of n*512
	_fill() {
		const l = this.size * 8;
		let len = this.chunk.push(0x80) % 64;
		if (64 - len < 8) {
			len -= 64;
		}
		for (; len < 56; len++) {
			this.chunk.push(0x00);
		}

		for (let i = 0; i < 4; i++) {
			const hi = Math.floor(l / 0x100000000);
			this.chunk.push((hi >>> ((3 - i) * 8)) & 0xff);
		}
		for (let i = 0; i < 4; i++) {
			this.chunk.push((l >>> ((3 - i) * 8)) & 0xff);
		}

	}
}

module.exports = SM3;



