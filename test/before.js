const certs = require('..');
const fs = require('fs-extra');
const pkiPath = `${__dirname}/pki`;

before('Create PKI directory', function(done) {
    fs.ensureDirSync(pkiPath);
    certs.createCACert('example', { basePath: pkiPath });
    done();
});