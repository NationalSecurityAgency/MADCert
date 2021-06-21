const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');

forge.options.usePureJavaScript = true;

const extensionsFilter = [
    'name',
    'cA',
    'critical',
    'digitalSignature',
    'nonRepudiation',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'encipherOnly',
    'decipherOnly',
    'subjectKeyIdentifier',
    'altNames',
    'serverAuth',
    'clientAuth',
    'codeSigning',
    'emailProtection',
    'timeStamping',
    'client',
    'server',
    'email',
    'objsign',
    'reserved:',
    'sslCA',
    'emailCA',
    'objCA',
];

/**
 * 
 * @param {Array} attributes 
 * @returns {String} Distinguished name
 */
function attributesToDN(attributes){
    let dn = '';
    for (let i=0; i<attributes.length; i++){
        const attribute = attributes[i];
        dn += `${attribute.shortName}=${attribute.value}${i<attributes.length-1 ? ',' : ''}`
    }
    return dn;
}

/**
 * 
 * @param {String} path Path to pem certificate
 * @param {Array} propertiesFilter Optional Array of Strings to filter response object properties by
 * @returns {Object} Simplified JSON representation of pem certificate
 */
const certToJSON = function certToJSON(path, propertiesFilter) {
    const crt = fs.readFileSync(path);
    const forgeCrtObj = forge.pki.certificateFromPem(crt.toString());

    const crtJSON = _.pick(forgeCrtObj, ['version', 'serialNumber', 'validity']);
    crtJSON.subject = attributesToDN(forgeCrtObj.subject.attributes);
    crtJSON.issuer = attributesToDN(forgeCrtObj.issuer.attributes);
    crtJSON['signature algorithm'] = forge.oids[forgeCrtObj.signatureOid];

    crtJSON.extensions = _.transform(forgeCrtObj.extensions, (result, value) => {
        result.push(_.pick(value, extensionsFilter));
    }, []);

    if(propertiesFilter)
        return _.pick(crtJSON, propertiesFilter);
    return crtJSON;
}


module.exports = certToJSON;
