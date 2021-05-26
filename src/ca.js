const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');

forge.options.usePureJavaScript = true;
const pki = forge.pki;

const subjectAttrs = require('./subjectAttributes');
const utils = require('./utils');
const normalizeName = utils.normalizeName;

function buildCACert(keys, options, caCert = null) {
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = utils.getSerial();

    const attrs = subjectAttrs(options);

    // Set the default expiration, then override with valid-from and/or valid-to
    const expired = _.get(options, 'expired', false);
    utils.setExpirationDate(cert, expired);

    if (options.validFrom) {
        // Parse the validFrom from ISO 8601 format
        cert.validity.notBefore = new Date(options.validFrom);
    }

    if (options.validTo) {
        // Parse the validTo from ISO 8601 format
        cert.validity.notAfter = new Date(options.validTo);
    }
    const caSubject = _.get(caCert, "subject.attributes", null);
    cert.setSubject(attrs);
    cert.setIssuer(caSubject ? caSubject : attrs);
    const extensions = [
        {
            name: 'basicConstraints',
            cA: true,
            critical: true,
        },
        {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            critical: true,
            cRLSign: true,
        },
        {
            name: 'subjectKeyIdentifier',
        },
    ];

    if(caCert){
        extensions.push({
            name: 'authorityKeyIdentifier',
            keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
        });
        extensions.push(
        {
            name: 'extKeyUsage',
            serverAuth: true,
            critical: true,
        });
    }

    cert.setExtensions(extensions);

    return cert;
}

function createCACert(caName, options) {
    let basePath = _.get(options, 'basePath', 'pki/');
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (options.validFrom && options.validTo) {
        const validFrom = new Date(options.validFrom);
        const validTo = new Date(options.validTo);
        if (validTo.getTime() < validFrom.getTime()) {
            console.log(
                `Expiration date ${options.validTo} before start date ${options.validFrom}, aborting creation of new CA certificate`
            );
            return;
        }
    }

    const caPath = basePath + normalizeName(caName) + '/ca/';
    if (!fs.existsSync(caPath)) {
        const keys = pki.rsa.generateKeyPair(2048);
        const cert = buildCACert(keys, options);

        fs.ensureDirSync(caPath);
        // self-sign certificate
        cert.sign(keys.privateKey, utils.createMessageDigest());
        // convert a Forge certificate to PEM
        const certPem = pki.certificateToPem(cert);
        const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
        //write out crt, key PEM, and serial.txt files
        fs.outputFileSync(caPath + '/' + 'crt.pem', certPem);
        fs.outputFileSync(caPath + '/' + 'key.pem', privateKeyPem);
        fs.outputFileSync(caPath + '/' + 'serial.txt', '01');

        console.log('Certificate authority ' + caName + ' was created.');
    } else {
        console.log('Certificate authority already exists');
    }
}

function createIntermediateCACert(caName, rootCaName, options) {
    let basePath = _.get(options, 'basePath', 'pki/');
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (options.validFrom && options.validTo) {
        const validFrom = new Date(options.validFrom);
        const validTo = new Date(options.validTo);
        if (validTo.getTime() < validFrom.getTime()) {
            console.log(
                `Expiration date ${options.validTo} before start date ${options.validFrom}, aborting creation of new intermediate CA certificate`
            );
            return;
        }
    }

    const newCaPath = basePath + normalizeName(caName) + '/ca/';
    const rootCaPath = basePath + normalizeName(rootCaName) + '/ca/';

    if (!fs.existsSync(rootCaPath)) {
        console.log(
            `Certificate Authority ${rootCaName} does not exist, aborting creation of new intermediate CA certificate`
        );
        return;
    }

    if (!fs.existsSync(newCaPath)) {
        // sign certificate with CA private key
        const caCertPem = fs.readFileSync(rootCaPath + '/crt.pem', 'utf8');
        const caCert = forge.pki.certificateFromPem(caCertPem);
        const rootCaKeyPem = fs.readFileSync(rootCaPath + '/key.pem', 'utf8');
        const caKey = forge.pki.privateKeyFromPem(rootCaKeyPem);

        const keys = pki.rsa.generateKeyPair(2048);
        const cert = buildCACert(keys, options, caCert);

        fs.ensureDirSync(newCaPath);
        // self-sign certificate
        cert.sign(caKey, utils.createMessageDigest());
        // convert a Forge certificate to PEM
        const certPem = pki.certificateToPem(cert);
        const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
        //write out crt, key PEM, and serial.txt files
        fs.outputFileSync(newCaPath + '/crt.pem', certPem);
        fs.outputFileSync(newCaPath + '/key.pem', privateKeyPem);
        fs.outputFileSync(newCaPath + '/serial.txt', '01');
        fs.outputFileSync(
            basePath + normalizeName(caName) + '/parent.txt',
            normalizeName(rootCaName)
        );

        const bundleFile = `${rootCaPath}/${normalizeName(rootCaName)}.ca-bundle`;
        if (!fs.existsSync(bundleFile)) {
            //TODO: Create bundle file
        } else {
            //TODO: Update bundle file
        }

        console.log('Certificate authority ' + caName + ' was created.');
    } else {
        console.log('Certificate authority already exists');
    }
}

function listCACerts(path) {
    utils.listCerts('ca', path);
}

function removeCACert(name, basePath = 'pki/') {
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (fs.existsSync(basePath + '/' + normalizeName(name))) {
        fs.removeSync(basePath + '/' + normalizeName(name));
        console.log(
            'Certificate Authority ' + name + ' and all associated certificates were removed.'
        );
    } else {
        console.log('Certificate Authority ' + name + ' does not exist.');
    }
}

module.exports = {
    createCACert,
    createIntermediateCACert,
    listCACerts,
    removeCACert,
};
