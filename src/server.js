const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');
const os = require('os');
const path = require('path');

forge.options.usePureJavaScript = true;
const pki = forge.pki;

const subjectAttrs = require('./subjectAttributes');
const utils = require('./utils');
const normalizeName = utils.normalizeName;

const DNS_TYPE = 2;
const IP_TYPE = 7;

const madcertLhSubjectAltDNSName = process.env.MADCERT_LH_SUBJECT_ALT_DNS_NAME || '';

function getIpAddresses() {
    const localIPs = [];

    // Pull the IP address
    const nic = os.networkInterfaces();
    for (let i in nic) {
        const names = nic[i];
        for (let j = 0; j < names.length; j++) {
            const k = names[j];
            if (k.family === 'IPv4' && k.address !== '127.0.0.1' && !k.internal) {
                localIPs.push(k.address);
            }
        }
    }

    return localIPs;
}

function buildServerCert(keys, caName, caCert, localhost, options) {
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
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
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

    // Create the subject alternative names if this is creating the localhost certificate
    if (localhost) {
        // If the environment variable MADCERT_LH_SUBJECT_ALT_DNS_NAME is not set use the hostname
        const localHostName = madcertLhSubjectAltDNSName || os.hostname();

        // Add to the extensions object
        altNames.push.apply(altNames, [
            {
                type: DNS_TYPE,
                value: localHostName,
            },
            {
                type: DNS_TYPE,
                value: 'localhost',
            },
            {
                type: IP_TYPE,
                ip: '127.0.0.1',
            },
        ]);

        const localIPs = getIpAddresses().map(ip => {
            return {
                type: IP_TYPE,
                ip,
            };
        });

        altNames.push.apply(altNames, localIPs);
    }

    // Add any subject alternative names provided on the command line
    _.each(_.get(options, 'subjectAltDnsNames', []), name => {
        altNames.push({
            type: DNS_TYPE,
            value: name,
        });
    });

    _.each(_.get(options, 'subjectAltIpNames', []), name => {
        altNames.push({
            type: IP_TYPE,
            ip: name,
        });
    });

    if (!_.isEmpty(altNames)) {
        extensions.push.apply(extensions, [{ name: 'subjectAltName', altNames: altNames }]);
    }

    // Add all extensions
    cert.setExtensions(extensions);

    return cert;
}

function createServerCert(
    serverName,
    caCertName,
    localhost,
    options,
    callback = (err, data) => {}
) {
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

    let expired = _.get(options, 'expired', false);

    // If valid-to was passed to madcert then check if it is in the past
    if (options.validTo) {
        const date = new Date(options.validTo);
        if (date.getTime() < new Date().getTime()) {
            expired = true;
        }
    }

    const password = _.get(options, 'password', 'changeme');

    const caPath = path.join(basePath, normalizeName(caCertName), '/ca/');
    const serverPath = path.join(basePath, normalizeName(caCertName), '/servers/');
    const serverDir = path.join(
        serverPath,
        normalizeName(serverName),
        options.expired ? '/expired' : ''
    );
    if (!fs.existsSync(caPath)) {
        const err = {
            message: `Certificate Authority ${caCertName} does not exist, aborting creation of new server certificate`,
        };
        console.error(err.message);
        callback(err);
        return;
    }

    // Adding a check for the common name to be populated
    // with the name field if it is blank.
    options.commonName = _.get(options, 'commonName', serverName);

    const serverCertPath = path.join(serverDir, '/crt.pem');
    const serverKeyPath = path.join(serverDir, '/key.pem');
    const serverP12Path = path.join(serverDir, '/bundle.p12');

    if (
        !fs.existsSync(serverDir) ||
        !fs.existsSync(serverCertPath) ||
        !fs.existsSync(serverKeyPath) ||
        !fs.existsSync(serverP12Path)
    ) {
        const keys = pki.rsa.generateKeyPair(2048);

        let rootCaCert;

        const rootCaName = _.get(options, 'rootCaName', null);
        if (rootCaName !== null) {
            const rootCaPath = path.join(basePath, normalizeName(rootCaName), '/ca/');
            if (!fs.existsSync(caPath)) {
                const err = {
                    message: `Root Certificate Authority ${rootCaName} does not exist, aborting creation of new server certificate`,
                };
                console.error(err.message);
                callback(err);
                return;
            }

            const rootCaCertPem = fs.readFileSync(path.join(rootCaPath, '/crt.pem'), 'utf8');
            rootCaCert = forge.pki.certificateFromPem(rootCaCertPem);
        }

        // sign certificate with CA private key
        const caCertPem = fs.readFileSync(path.join(caPath, '/crt.pem'), 'utf8');
        const caCert = forge.pki.certificateFromPem(caCertPem);
        const caKeyPem = fs.readFileSync(path.join(caPath, '/key.pem'), 'utf8');
        const caKey = forge.pki.privateKeyFromPem(caKeyPem);

        const cert = buildServerCert(
            keys,
            caCertName,
            caCert,
            localhost,
            options
        );
        fs.ensureDirSync(serverPath);

        cert.sign(caKey, utils.createMessageDigest());

        // convert a Forge certificate to PEM
        const pem = pki.certificateToPem(cert);
        fs.outputFileSync(serverCertPath, pem);

        const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
        fs.outputFileSync(serverKeyPath, privateKeyPem);

        let p12Asn1;
        //create .p12 file
        if (rootCaCert) {
            p12Asn1 = forge.pkcs12.toPkcs12Asn1(
                keys.privateKey,
                [cert, caCertPem, rootCaCert],
                password,
                {
                    algorithm: '3des',
                }
            );
        } else {
            p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert, caCertPem], password, {
                algorithm: '3des',
            });
        }
        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        fs.writeFileSync(serverP12Path, p12Der, {
            encoding: 'binary',
        });

        const success = {
            message: `${serverName} ${
                expired ? 'expired ' : ''
            }server certificate was created and signed by ${caCertName}.`,
        };
        console.error(success.message);
        callback(null, success);
    } else {
        const err = {
            message: `${serverName} ${
                expired ? 'expired ' : ''
            }server certificate already exists in ${caCertName}.`,
        };
        console.error(err);
        callback(err);
    }
}

function listServerCerts(path) {
    utils.listCerts('servers', path);
}

function removeServerCert(name, caName, basePath = 'pki/', callback) {
    utils.removeCerts('servers', name, caName, basePath, callback);
}

module.exports = {
    createServerCert,
    listServerCerts,
    removeServerCert,
};
