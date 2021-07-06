const fs = require('fs-extra');
const _ = require('lodash');
const path = require('path');

const caDb = require('./caDatabase');
const ca = require('./ca');
const server = require('./server');
const user = require('./user');
const utils = require('./utils');
const normalizeName = utils.normalizeName;
const createSubjectAttributes = require('./subjectAttributes');
const certToJSON = require('./certToJSON');

function jsonListCerts(basePath = 'pki/') {
    const certs = {};

    if (basePath.substr(-1) !== '/') basePath += '/';

    if (fs.existsSync(basePath)) {
        certs.ca = [];
        const files = fs.readdirSync(basePath);

        _.forEach(files, filename => {
            if (fs.lstatSync(basePath + filename).isDirectory()) {
                const caCerts = {
                    name: filename,
                    servers: [],
                    users: [],
                };
                const tempServersBase = `${basePath}${filename}/servers/`;
                if (fs.existsSync(tempServersBase)) {
                    const serverFiles = fs.readdirSync(tempServersBase);
                    _.forEach(serverFiles, serverName => {
                        caCerts.servers.push(serverName);
                    });
                }

                const tempUsersBase = `${basePath}${filename}/users/`;
                if (fs.existsSync(tempUsersBase)) {
                    const userFiles = fs.readdirSync(tempUsersBase);
                    _.forEach(userFiles, userName => {
                        caCerts.users.push(userName);
                    });
                }

                certs.ca.push(caCerts);
            }
        });
    }
    return certs;
}

function getCertFilenames(type, caName, basePath) {
    let certs = [];

    if (!basePath.endsWith('/')) basePath += '/';
    const certDir = `${basePath}${normalizeName(caName)}/${type}`;

    if (fs.existsSync(certDir)) {
        const certNames = fs.readdirSync(certDir);

        certNames.forEach(certName => {
            if (fs.existsSync(`${certDir}/${certName}/crt.pem`)) {
                certs.push(`${certDir}/${certName}/crt.pem`);
            }
            if (fs.existsSync(`${certDir}/${certName}/expired/crt.pem`)) {
                certs.push(`${certDir}/${certName}/expired/crt.pem`);
            }
        });
    }

    return certs;
}

function createCertDatabase(caName, { basePath = 'pki/', revokedCNs = [] } = {}) {
    const serverCerts = getCertFilenames('users', caName, basePath);
    const userCerts = getCertFilenames('servers', caName, basePath);
    caDb.create(
        userCerts.concat(serverCerts),
        `${basePath}/${normalizeName(caName)}/ca/index.txt`,
        revokedCNs
    );
}

function caCertToJSONWrapper(basePath, caName, propertiesFilter){
    const certPath = basePath ? path.join(basePath, normalizeName(caName), 'ca/crt.pem') : path.join(__dirname, 'pki', normalizeName(caName), 'ca/crt.pem');
    return certToJSON(certPath, propertiesFilter);
}

function serverCertToJSONWrapper(basePath, caName, serverName, propertiesFilter){
    const certPath = basePath ? path.join(basePath, normalizeName(caName), 'servers', serverName, 'crt.pem') : path.join(__dirname, 'pki', normalizeName(caName), 'servers', serverName, 'crt.pem');
    return certToJSON(certPath, propertiesFilter);
}

function userCertToJSONWrapper(basePath, caName, userName, propertiesFilter){
    const certPath = basePath ? path.join(basePath, normalizeName(caName), 'users', userName, 'crt.pem') : path.join(__dirname, 'pki', normalizeName(caName), 'users', userName, 'crt.pem');
    return certToJSON(certPath, propertiesFilter);
}

const certs = {
    createCACert: ca.createCACert,
    createIntermediateCACert: ca.createIntermediateCACert,
    listCACerts: ca.listCACerts,
    removeCACert: ca.removeCACert,
    createServerCert: server.createServerCert,
    listServerCerts: server.listServerCerts,
    removeServerCert: server.removeServerCert,
    createUserCert: user.createUserCert,
    listUserCerts: user.listUserCerts,
    removeUserCert: user.removeUserCert,
    listCerts: jsonListCerts,
    createCertDatabase,
    normalizeName,
    createSubjectAttributes,
    caCertToJSON: caCertToJSONWrapper,
    serverCertToJSON: serverCertToJSONWrapper,
    userCertToJSON: userCertToJSONWrapper,
};

module.exports = certs;
