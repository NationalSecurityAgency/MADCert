const fs = require('fs-extra');

after('Remove PKI directory', function() {
    fs.removeSync(global.pkiPath);
});