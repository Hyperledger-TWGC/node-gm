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
const utils = require('./sm_utils');
const elliptic = require('elliptic');
const BN = require('bn.js');
const DRBG = require('hmac-drbg'); // indirect loaded
const hash = require('hash.js'); // indirect loaded

const _drbg = new DRBG({
	hash: hash.sha256,
	entropy: 'UQi4W3Y2bJfzleYy+oEZ2kA9A+9jrmwewST9vmBZNgMmFyzzH0S9Vol/UK',
	nonce: '0123456789avcdef',
	pers: '0123456789abcdef'
});


const _sm2Params = {
	type: 'SM2',
	prime: null,
	p: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF',
	a: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC',
	b: '28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93',
	n: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123',
	hash: sm3,
	gRed: false,
	g: [
		'32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7',
		'BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0'
	]

};

/**
 * The SM2 elliptic curve
 */
class SM2Curve extends elliptic.curve.short {
	constructor(params) {
		super(params);
	}

	/**
	 * Return a point on the curve.
	 * Will throw error if (x,y) is not on curve.
	 *
	 * @param {string} x - coordinate x in hex string
	 * @param {string} y - coordinate y in hex string
	 * @param {string} parity - determine the value of y, could be 'odd' or 'even' (default), ignored when y is not null
	 */
	_sm2Point(x, y, parity) {
		if (!x) {
			return this.point();
		}

		let pt;
		if (y) {
			pt = this.point(x, y);
			if (!this.validate(pt)) {
				throw Error('point is not on curve');
			}
		} else {
			const px = new BN(x, 16).toRed(this.red);
			let py = px.redSqr().redMul(px);
			py = py.redIAdd(px.redMul(this.a)).redIAdd(this.b).redSqrt();
			if ((parity === 'odd') !== py.fromRed().isOdd()) {
				py = py.redNeg();
			}
			pt = this.point(px, py);
		}

		return pt;
	}
}


/**
 * SM2 public and private key pair
 *
 */
class SM2KeyPair {
	/**
	 * Either `pub` and `pri` can be a hex string or byte array or null.
	 * @param pub - If `pub` is a string, it should be the same format as output of pubToString().
	 * @param pri
	 */
	constructor(pub, pri) {
		const SM2 = new SM2Curve(_sm2Params); // curve parameter
		this.curve = SM2;
		this.pub = null; // public key, should be a point on the curve
		this.pri = null; // private key, should be a integer

		let validPub = false;
		let validPri = false;

		if (pub) {
			if (typeof pub === 'string') {
				this._pubFromString(pub);
			} else if (Array.isArray(pub)) {
				this._pubFromBytes(pub);
			} else if ('x' in pub && pub.x instanceof BN && 'y' in pub && pub.y instanceof BN) {
				// pub is already the Point object
				this.pub = pub;
				validPub = true;
			} else {
				throw Error('invalid public key');
			}
		}
		if (pri) {
			if (typeof pri === 'string') {
				this.pri = new BN(pri, 16);
			} else if (pri instanceof BN) {
				this.pri = pri;
				validPri = true;
			} else {
				throw Error('invalid private key');
			}

			// calculate public key
			if (this.pub === null) {
				this.pub = SM2.g.mul(this.pri);
			}
		}

		if (!(validPub && validPri) && !this.validate()) {
			throw Error('invalid key');
		}
	}

	/**
	 * Convert the public key to the hex string format
	 *
	 * @param {Number} [mode='nocompress'] - compressing mode, available values:
	 *    'compress', 'nocompress', 'mix'
	 */
	pubToString(mode) {
		let s;
		switch (mode) {
			case 'compress':
				if (this.pub.getY().isEven()) {
					s = '02';
				} else {
					s = '03';
				}
				return s + this.pub.getX().toString(16, 32);
			case 'mix':
				if (this.pub.getY().isEven()) {
					s = '06';
				} else {
					s = '07';
				}
				break;
			default:
				s = '04';
		}
		return s + this.pub.getX().toString(16, 32) + this.pub.getY().toString(16, 32);
	}

	/**
	 * @private
	 * Parse public key from hex string.
	 */
	_pubFromString(s) {
		const err = Error('invalid key string');
		if (s.length < 66) {
			throw err;
		}
		const x = s.slice(2, 66);
		switch (s.slice(0, 2)) {
			case '00':
				throw Error('public key should not be infinity');
			case '02':
				this.pub = this.curve._sm2Point(x, null, 'even');
				break;
			case '03':
				this.pub = this.curve._sm2Point(x, null, 'odd');
				break;
			case '04':
			case '06':
			case '07':
				if (s.length < 130) {
					throw err;
				}
				this.pub = this.curve._sm2Point(x, s.slice(66, 130));
				break;
			default:
				throw err;
		}
	}

	/**
	 * @private
	 * Parse public key from byte array.
	 */
	_pubFromBytes(b) {
		const err = Error('unrecognized key');
		if (b.length < 33) {
			throw err;
		}
		const x = b.slice(1, 33);
		switch (b[0]) {
			case 0x00:
				throw Error('public key should not be infinity');
			case 0x02:
				this.pub = this.curve._sm2Point(x, null, 'even');
				break;
			case 0x03:
				this.pub = this.curve._sm2Point(x, null, 'odd');
				break;
			case 0x04:
			case 0x06:
			case 0x07:
				if (b.length < 65) {
					throw err;
				}
				this.pub = this.curve._sm2Point(x, b.slice(33, 65));
				break;
			default:
				throw err;
		}
	}

	/**
	 * Check whether the public key is valid.
	 *
	 * @return {boolean}
	 */
	validate() {
		if (this.pub) {
			if (this.pub.isInfinity()) {
				return false;
			}

			if (!this.curve.validate(this.pub)) {
				return false;
			}

			if (!this.pub.mul(this.curve.n).isInfinity()) {
				return false;
			}
		}

		if (this.pri) {
			if (this.pri.cmp(this.curve.n.sub(new BN(2))) > 0) {
				return false;
			}

			if (this.pub !== null && !this.pub.eq(this.curve.g.mul(this.pri))) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Convert the public key to a byte array.
	 * The value of X and Y will be stored in big endian.
	 *
	 * @param {string} mode - compressing mode, same as pubToString.
	 */
	pubToBytes(mode) {
		const a = [];
		switch (mode) {
			case 'compress':
				if (this.pub.getY().isEven()) {
					a.push(0x02);
				} else {
					a.push(0x03);
				}
				return a.concat(this.pub.getX().toArray('be', 32));
			case 'mix':
				if (this.pub.getY().isEven()) {
					a.push(0x06);
				} else {
					a.push(0x07);
				}
				break;
			default:
				a.push(0x04);
		}
		return a.concat(this.pub.getX().toArray('be', 32)).concat(this.pub.getY().toArray('be', 32));
	}

	/**
	 * Generate signature to the message
	 *
	 * The input message will combine with extras(a constant user id, the
	 * curve parameters and public key), and use SM3 hashing function to
	 * generate digest.
	 *
	 * @param {string|buffer} msg
	 *
	 * @return {object} Signature (r, s). Both part is a hex string.
	 */
	sign(msg) {
		if (!this.pri) {
			throw Error('cannot sign message without private key');
		}
		if (typeof msg === 'string') {
			return this.signDigest(new sm3().sum(this._combine(utils.strToBytes(msg))));
		} else {
			return this.signDigest(new sm3().sum(this._combine(msg)));
		}
	}

	/**
	 * Verify the signature (r,s)
	 *
	 * @param {string|buffer} msg
	 * @param {string} r - signature.r part in hex string
	 * @param {string} s - signature.s part in hex string
	 *
	 * @return {boolean} true if verification passed.
	 */
	verify(msg, r, s) {
		if (!this.pub) {
			throw Error('cannot verify signature without public key');
		}
		return this.verifyDigest(new sm3().sum(this._combine(msg)), r, s);
	}

	/**
	 * Generate signature to the message without combination with extras.
	 */
	signRaw(msg) {
		return this.signDigest(new sm3().sum(msg));
	}

	/**
	 * Verify signature (r, s) generated by signRaw()
	 */
	verifyRaw(msg, r, s) {
		return this.verifyDigest(new sm3().sum(msg), r, s);
	}

	/**
	 * Generate signature for the message digest
	 *
	 * The input data should be a 256bits hash digest.
	 *
	 * @param {string|buffer} digest - the digest of the message
	 * @return {object}  signature with r and s parts
	 */
	signDigest(digest) {
		const signature = {
			r: '',
			s: ''
		};
		// eslint-disable-next-line no-constant-condition
		while (true) {
			const k = new BN(_drbg.generate(32, 'hex', utils.random(64)), 16).umod(this.curve.n);
			const kg = this.curve.g.mul(k);
			const r = utils.hashToBN(digest).add(kg.getX()).umod(this.curve.n);
			// r = 0
			if (r.isZero()) {
				continue;
			}
			// r + k = n
			if (r.add(k).eq(this.curve.n)) {
				continue;
			}

			const t1 = new BN(1).add(this.pri).invm(this.curve.n);
			const t2 = k.sub(r.mul(this.pri)).umod(this.curve.n);
			const s = t1.mul(t2).umod(this.curve.n);
			if (!s.isZero()) {
				signature.r = r.toString(16);
				signature.s = s.toString(16);
				break;
			}
		}

		return signature;
	}


	/**
	 * Verify the signature to the digest
	 *
	 * @param {string|buffer} digest - digest of the message
	 * @param {string} r - hex string of signature.r
	 * @param {string} s - hex string of signature.s
	 *
	 * @return {boolean} true if verification passed
	 */
	verifyDigest(digest, r, s) {
		const bnr = new BN(r, 16);
		if (bnr.cmp(this.curve.n) >= 0) {
			return false;
		}

		const bns = new BN(s, 16);
		if (bns.cmp(this.curve.n) >= 0) {
			return false;
		}

		const t = bnr.add(bns).umod(this.curve.n);
		if (t.isZero()) {
			return false;
		}

		const q = this.curve.g.mul(bns).add(this.pub.mul(t));
		const R = utils.hashToBN(digest).add(q.getX()).umod(this.curve.n);
		return R.eq(bnr);
	}

	_combine(msg) {
		let za = [0x00, 0x80, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
		za = za.concat(this.curve.a.fromRed().toArray());
		za = za.concat(this.curve.b.fromRed().toArray());
		za = za.concat(this.curve.g.getX().toArray());
		za = za.concat(this.curve.g.getY().toArray());
		za = za.concat(this.pub.getX().toArray());
		za = za.concat(this.pub.getY().toArray());

		const h = new sm3();
		za = h.sum(za);

		if (typeof msg === 'string') {
			return za.concat(utils.strToBytes(msg));
		} else {
			return za.concat(msg);
		}
	}

	toString() {
		let s = 'public: ';
		if (this.pub) {
			s += '(' + this.pub.getX().toString(16) + ', ' + this.pub.getY().toString(16) + ')';
		} else {
			s += 'null';
		}
		s += ', private: ';
		if (this.pri) {
			s += this.pri.toString(16);
		} else {
			s += 'null';
		}
		return s;
	}
}

/**
 * Generate a SM2 key pair
 */
const genKeyPair = () => {
	let pri = 0;
	const sm2Curve = new SM2Curve(_sm2Params);
	const limit = sm2Curve.n.sub(new BN(2));
	// generate 32 bytes private key in range [1, n-1]
	do {
		pri = new BN(_drbg.generate(32, 'hex', utils.random(64)));
	} while (pri.cmp(limit) > 0);

	return new SM2KeyPair(null, pri);
};

module.exports = {
	genKeyPair,
	SM2Curve,
	SM2CurveDefaultParams: _sm2Params,
	SM2KeyPair,
};








