const _ = require('lodash');

function createSubjectAttributes(options) {
    const attrs = [];

    const country = _.get(options, 'country', 'US');
    attrs.push({
        shortName: 'C',
        value: country,
    });

    const orgs = _.get(options, 'organizations', []);
    _.each(orgs, org => {
        attrs.push({
            shortName: 'O',
            value: org,
        });
    });

    const ous = _.get(options, 'organizationalUnits', []);
    _.each(ous, ou => {
        attrs.push({
            shortName: 'OU',
            value: ou,
        });
    });

    const cn = _.get(options, 'commonName');
    if (cn) {
        attrs.push({
            shortName: 'CN',
            value: cn,
        });
    }

    const l = _.get(options, 'locality');
    if (l) {
        attrs.push({
            shortName: 'L',
            value: l,
        });
    }

    const st = _.get(options, 'state');
    if(st) {
        attrs.push({
            shortName: 'ST',
            value: st,
        });
    }
    return attrs;
}

module.exports = createSubjectAttributes;
