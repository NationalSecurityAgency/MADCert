const fs = require('fs-extra');
const pkiPath = `${__dirname}/pki`;

after('Remove PKI directory', function() {
    fs.removeSync(pkiPath);
});