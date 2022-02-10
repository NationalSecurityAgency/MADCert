const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');

forge.options.usePureJavaScript = true;
const pki = forge.pki;

const subjectAttrs = require('./subjectAttributes');
const utils = require('./utils');
const normalizeName = utils.normalizeName;

function buildUserCert(keys, options, caCert) {
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = utils.getSerial();

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

    const attrs = subjectAttrs(options);

    cert.setSubject(attrs);
    cert.setIssuer(caCert.subject.attributes);
    const extensions = [
        {
            name: 'basicConstraints',
            cA: false,
            critical: true,
        },
        {
            name: 'keyUsage',
            digitalSignature: true,
            keyEncipherment: true,
            critical: true,
        },
        {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            emailProtection: true,
        },
        {
            name: 'subjectKeyIdentifier',
        },
        {
            name: 'authorityKeyIdentifier',
            keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
        },
    ];

    const altNames = [];

    // Add any subject alternative names provided on the command line
    _.each(_.get(options, 'subjectAltEmailNames', []), name => {
        altNames.push({
            type: 1, // rfc822Name
            value: name,
        });
    });

    if (!_.isEmpty(altNames)) {
        extensions.push.apply(extensions, [{ name: 'subjectAltName', altNames: altNames }]);
    }

    // Add all extensions
    cert.setExtensions(extensions);

    return cert;
}

function createUserCert(userName, caCertName, options, callback = (err, data) => {}) {
    let basePath = _.get(options, 'basePath', 'pki/');
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (options.validFrom && options.validTo) {
        const validFrom = new Date(options.validFrom);
        const validTo = new Date(options.validTo);
        if (validTo.getTime() < validFrom.getTime()) {
            const err = {
                message: `Expiration date ${options.validTo} before start date ${options.validFrom}, aborting creation of new server certificate`,
            };
            console.error(err.message);
            callback(err);
            return;
        }
    }

    const caPath = basePath + normalizeName(caCertName) + '/ca/';
    const userPath = basePath + normalizeName(caCertName) + '/users/';

    let expired = _.get(options, 'expired', false);

    // If valid-to was passed to madcert then check if it is in the past
    if (options.validTo) {
        const date = new Date(options.validTo);
        if (date.getTime() < new Date().getTime()) {
            expired = true;
        }
    }

    const password = _.get(options, 'password', 'changeme');

    const userDir = userPath + normalizeName(userName) + (expired ? '/expired' : '');
    if (!fs.existsSync(caPath)) {
        const err = {
            message: `Certificate Authority ${caCertName} does not exist, aborting creation of new user certificate`,
        };
        console.error(err.message);
        callback(err);
        return;
    }

    // Adding a check for the common name to be populated
    // with the name field if it is blank.
    options.commonName = _.get(options, 'commonName', userName);

    const userCertPath = userDir + '/crt.pem';
    const userKeyPath = userDir + '/key.pem';
    const userP12Path = userDir + '/bundle.p12';

    if (
        !fs.existsSync(userDir) ||
        !fs.existsSync(userCertPath) ||
        !fs.existsSync(userKeyPath) ||
        !fs.existsSync(userP12Path)
    ) {
        const keys = pki.rsa.generateKeyPair(2048);

        let rootCaCert;

        const rootCaName = _.get(options, 'rootCaName', null);
        if (rootCaName !== null) {
            const rootCaPath = basePath + normalizeName(rootCaName) + '/ca/';
            if (!fs.existsSync(caPath)) {
                const err = {
                    message: `Root Certificate Authority ${rootCaName} does not exist, aborting creation of new user certificate`,
                };
                console.error(err.message);
                callback(err);
                return;
            }

            const rootCaCertPem = fs.readFileSync(rootCaPath + '/crt.pem', 'utf8');
            rootCaCert = forge.pki.certificateFromPem(rootCaCertPem);
        }

        fs.ensureDirSync(userPath);

        // sign certificate with CA private key
        const caCertPem = fs.readFileSync(caPath + '/crt.pem', 'utf8');
        const caCert = forge.pki.certificateFromPem(caCertPem);
        const caKeyPem = fs.readFileSync(caPath + '/key.pem', 'utf8');
        const caKey = forge.pki.privateKeyFromPem(caKeyPem);

        const cert = buildUserCert(keys, options, caCert);

        cert.sign(caKey, utils.createMessageDigest());

        // convert a Forge certificate to PEM
        const pem = pki.certificateToPem(cert);
        fs.outputFileSync(userCertPath, pem);

        const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
        fs.outputFileSync(userKeyPath, privateKeyPem);

        let p12Asn1;
        //create .p12 file
        if (rootCaCert) {
            p12Asn1 = forge.pkcs12.toPkcs12Asn1(
                keys.privateKey,
                [cert, caCert, rootCaCert],
                password,
                {
                    algorithm: '3des',
                }
            );
        } else {
            p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert, caCert], password, {
                algorithm: '3des',
            });
        }

        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        fs.writeFileSync(userP12Path, p12Der, {
            encoding: 'binary',
        });

        const success = {
            message: `${userName} ${
                expired ? 'expired ' : ''
            }user certificate was created and signed by ${caCertName}.`,
        };

        console.log(success.message);
        callback(null, success);
    } else {
        const err = {
            message: `${userName} ${
                expired ? 'expired ' : ''
            }user certificate already exists in ${caCertName}.`,
        };
        console.error(err.message);
        callback(err);
    }
}

function listUserCerts(path) {
    return utils.listCerts('users', path);
}

function removeUserCert(name, caName, basePath = 'pki/', callback) {
    utils.removeCerts('users', name, caName, basePath, callback);
}

module.exports = {
    createUserCert,
    listUserCerts,
    removeUserCert,
};