#!/usr/bin/env node

const version = require('../package.json').version;

const yargs = require('yargs');
const certs = require('./certs');

let executed = false;
const argv = yargs
    .scriptName('madcert')
    .usage('madcert <cmd>')
    .command('ca-create <name>', 'create a certificate authority', {}, function(argv) {
        executed = true;
        certs.createCACert(argv.name, {
            basePath: argv.path,
            commonName: argv['common-name'],
            country: argv.country,
            expired: argv.expired,
            organizations: argv.org,
            organizationalUnits: argv['org-unit'],
            validFrom: argv['valid-from'],
            validTo: argv['valid-to'],
        });
    })
    .command(
        'ca-intermediate-create <name> <root_ca_name>',
        'create an intermediate certificate authority',
        {},
        function(argv) {
            executed = true;
            certs.createIntermediateCACert(argv.name, argv.root_ca_name, {
                basePath: argv.path,
                commonName: argv['common-name'],
                country: argv.country,
                expired: argv.expired,
                organizations: argv.org,
                organizationalUnits: argv['org-unit'],
                validFrom: argv['valid-from'],
                validTo: argv['valid-to'],
            });
        }
    )
    .command('ca-list', 'list certificate authorities', {}, function(argv) {
        executed = true;
        certs.listCACerts(argv.path);
    })
    .command(
        'ca-remove <name>',
        'remove a certificate authority and all associated users and servers',
        {},
        function(argv) {
            executed = true;
            certs.removeCACert(argv.name, argv.path);
        }
    )
    .command('server-create <name> <ca_name>', 'create a server certificate', {}, function(argv) {
        executed = true;
        certs.createServerCert(argv.name, argv.ca_name, argv.localhost, {
            basePath: argv.path,
            commonName: argv['common-name'],
            country: argv.country,
            expired: argv.expired,
            organizations: argv.org,
            organizationalUnits: argv['org-unit'],
            password: argv.password,
            rootCaName: argv['root-ca-name'],
            subjectAltDnsNames: argv['subject-alt-dns'],
            subjectAltIpNames: argv['subject-alt-ip'],
            validFrom: argv['valid-from'],
            validTo: argv['valid-to'],
        });
    })
    .command('server-list', 'list server certificates', {}, function(argv) {
        executed = true;
        certs.listServerCerts(argv.path);
    })
    .command('server-remove <name> <ca_name>', 'remove a server certificate', {}, function(argv) {
        executed = true;
        certs.removeServerCert(argv.name, argv.ca_name, argv.path);
    })
    .command('user-create <name> <ca_name>', 'create a user certificate', {}, function(argv) {
        executed = true;
        certs.createUserCert(argv.name, argv.ca_name, {
            basePath: argv.path,
            commonName: argv['common-name'],
            country: argv.country,
            expired: argv.expired,
            rootCaName: argv['root-ca-name'],
            organizations: argv.org,
            organizationalUnits: argv['org-unit'],
            password: argv.password,
            subjectAltEmailNames: argv['subject-alt-email'],
            validFrom: argv['valid-from'],
            validTo: argv['valid-to'],
        });
    })
    .command('user-list', 'list user certificates', {}, function(argv) {
        executed = true;
        certs.listUserCerts(argv.path);
    })
    .command('user-remove <name> <ca_name>', 'remove a user certificates', {}, function(argv) {
        executed = true;
        certs.removeUserCert(argv.name, argv.ca_name, argv.path);
    })
    .command(
        'create-db <ca_name>',
        'create an openssl database file from existing certs',
        {},
        function(argv) {
            executed = true;
            certs.createCertDatabase(argv.ca_name, {
                basePath: argv.path ? argv.path : undefined,
            });
        }
    )
    .option('path', {
        alias: 'p',
        describe: 'Base path for pki.',
        default: 'pki/',
        requiresArg: true,
    })
    .option('common-name', {
        alias: 'n',
        describe: 'Common Name in the Distinguished Name.',
        requiresArg: true,
    })
    .option('country', {
        alias: 'c',
        describe: 'Country.',
        default: 'US',
        requiresArg: true,
    })
    .option('expired', {
        alias: 'e',
        describe: 'Create an expired certificate.',
        type: 'boolean',
    })
    .option('org', {
        alias: 'o',
        describe: 'Organization name. This option can be specified multiple times.',
        type: 'array',
        requiresArg: true,
    })
    .option('org-unit', {
        alias: 'u',
        describe: 'Organizational unit name. This option can be specified multiple times.',
        type: 'array',
        requiresArg: true,
    })
    .option('root-ca-name', {
        alias: 'r',
        describe: 'Root CA name.',
        requiresArg: true,
    })
    .option('localhost', {
        alias: 'l',
        describe: 'Create a localhost server certificate with subject alternative names.',
        type: 'boolean',
        default: false,
    })
    .option('password', {
        alias: 'w',
        describe: 'Create the key with the the password (defaults to "changeme").',
        type: 'string',
        default: 'changeme',
        requiresArg: true,
    })
    .option('subject-alt-dns', {
        alias: 'd',
        describe:
            'Create certificate with DNS subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('subject-alt-ip', {
        alias: 'i',
        describe:
            'Create certificate with IP subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('subject-alt-email', {
        alias: ['m', 'subject-alt-rfc822'],
        describe:
            'Create certificate with rfc822/email subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('valid-from', {
        alias: 'f',
        describe: 'Valid from date in ISO 8601 format.',
        requiresArg: true,
    })
    .option('valid-to', {
        alias: 't',
        describe: 'Valid to date in ISO 8601 format.',
        requiresArg: true,
    })
    .alias('version', 'v')
    .alias('h', 'help')
    .conflicts('expired', 'valid-to')
    .version(version)
    .help('help')
    .group('common-name', 'Creation Options:')
    .group('country', 'Creation Options:')
    .group('expired', 'Creation Options:')
    .group('org-unit', 'Creation Options:')
    .group('org', 'Creation Options:')
    .group('root-ca-name', 'Creation Options:')
    .group('valid-from', 'Creation Options:')
    .group('valid-to', 'Creation Options:')
    .group('password', 'User Creation Options:')
    .group('subject-alt-email', 'User Creation Options:')
    .group('localhost', 'Server Creation Options:')
    .group('password', 'Server Creation Options:')
    .group('subject-alt-dns', 'Server Creation Options:')
    .group('subject-alt-ip', 'Server Creation Options:')
    .wrap(yargs.terminalWidth()).argv;

if (!executed) {
    yargs.showHelp();
}
