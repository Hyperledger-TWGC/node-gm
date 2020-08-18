const {SM2Curve, SM2KeyPair, SM2CurveDefaultParams, genKeyPair} = require('../sm_sm2');
describe('SM2: unit tests', () => {
	it('constructor', () => {
		new SM2Curve(SM2CurveDefaultParams);
		new SM2KeyPair();
		genKeyPair();
	});
});