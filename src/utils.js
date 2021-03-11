const forge = require('node-forge');
const fs = require('fs-extra');
const _ = require('lodash');
const moment = require('moment');
const path = require('path');

forge.options.usePureJavaScript = true;

function getSerial() {
    return moment().format('x'); // Current time formatted in milliseconds since the epoch.
}

function listCerts(type, basePath = 'pki/') {
    const certs = [];

    if (basePath.substr(-1) !== '/') basePath += '/';

    if (fs.existsSync(basePath)) {
        const files = fs.readdirSync(basePath);

        _.forEach(files, (c, i) => {
            if(fs.lstatSync(basePath + c).isDirectory()){
                if (type !== 'ca') {
                    if (type === 'users') {
                        console.log('User certificates for ' + c + ':');
                    } else {
                        console.log('Server certificates for ' + c + ':');
                    }
                    const tempBase = basePath + c + '/' + type + '/';
                    if (fs.existsSync(tempBase)) {
                        const files = fs.readdirSync(tempBase);
                        _.forEach(files, c => {
                            certs.push(c);
                            console.log('\t' + c);
                        });
                    }
                } else {
                    if (i === 0) {
                        console.log('Available Certificate Authorities:');
                    }
                        certs.push(c);
                        console.log('\t' + c);
                }
            }
        });
    }

    return certs;
}

// Converts name to file path friendly name
function normalizeName(name) {
    return name.replace(/\s+/g, '-').toLowerCase();
}

function removeCerts(type, name, caName, basePath = 'pki/', callback = (err, data) => {}) {
    if (basePath.substr(-1) !== '/') basePath += '/';

    const certDir = path.join(basePath, normalizeName(caName), type, normalizeName(name));

    if (fs.existsSync(certDir)) {
        fs.removeSync(certDir);
        const success = {
            message: `${name} was removed from ${caName}.`,
        };
        console.log(success.message);
        callback(null, success);
    } else {
        const error = {
            message: `${name} does not exist for ${caName}.`,
        };
        console.error(error.message);
        callback(error);
    }
}

function setExpirationDate(cert, expired) {
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();

    // if expired, set cert to be valid starting 5 years before today
    // if not expired, set cert to be valid starting yesterday
    expired
        ? cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 5)
        : cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);

    // if expired, set cert to be valid until yesterday
    // if not expired, set cert to be valid until 5 years from today
    expired
        ? cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() - 1)
        : cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 5);
}

function setValidFrom(cert, date) {}

function setValidTo(cert, date) {}

function createMessageDigest() {
    return forge.md.sha384.create();
}

module.exports = {
    createMessageDigest,
    getSerial,
    listCerts,
    normalizeName,
    removeCerts,
    setExpirationDate,
};
