const {SM2Curve, SM2KeyPair, SM2CurveDefaultParams, genKeyPair} = require('../sm_sm2');
require('should');
describe('SM2: unit tests', () => {
	it('constructor', () => {
		new SM2Curve(SM2CurveDefaultParams);
		new SM2KeyPair();
		genKeyPair();
	});
	it('sign and verify', () => {
		const keyPair = genKeyPair();
		const message = 'abc';
		const signature = keyPair.sign(message);

		const verifyResult = keyPair.verify(message, signature);
		verifyResult.should.equal(true);
	});
});