const certToJSON = require('../src/certToJSON');
const expect = require('chai').expect;
const path = require('path');
const util = require('util');
const pkiPath = `${__dirname}/pki`;

describe('Testing certToJSON.js', function() {
    it('Converts a PEM certificate to JSON', function() {
        const certJSON = certToJSON(path.join(pkiPath, 'example/ca/crt.pem'));
        expect(certJSON).to.be.an('object');
        expect(certJSON).to.include.all.keys('version', 'serialNumber', 'validity', 'subject', 'issuer', 'signature algorithm', 'extensions');
    });

    it('Filters properties in returned JSON object', function(){
        const propertiesArray = ['subject', 'issuer'];
        const certJSON = certToJSON(path.join(pkiPath, 'example/ca/crt.pem'), propertiesArray);
        expect(certJSON).to.be.an('object');
        expect(Object.keys(certJSON)).to.deep.equal(propertiesArray)
    });
});
