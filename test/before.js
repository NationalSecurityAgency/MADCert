const certs = require('..');
const fs = require('fs-extra');

before('Create PKI directory', function(done) {
    global.pkiPath = `${__dirname}/pki`;
    fs.ensureDirSync(global.pkiPath);
    certs.createCACert('example', { basePath: global.pkiPath });
    done();
});