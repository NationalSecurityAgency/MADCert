const _ = require('lodash');
const certs = require('..');
const fs = require('fs-extra');
const path = require('path');
const expect = require('chai').expect;

describe('Testing MADCert', function() {
    describe('CA Tests', function() {
        it('Create CA Cert', function(done) {
            try {
                certs.createCACert('CA Cert', { basePath: global.pkiPath });
                const created = fs.pathExistsSync(path.join(global.pkiPath, 'ca-cert/ca/crt.pem'));
                expect(created).to.be.true;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('Create intermediate CA Cert', function(done) {
            try {
                certs.createIntermediateCACert('CA Cert 2', 'CA Cert', { basePath: global.pkiPath });
                const created = fs.pathExistsSync(path.join(global.pkiPath, 'ca-cert-2/ca/crt.pem'));
                expect(created).to.be.true;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('List CA Certs', function() {
            certs.listCACerts(global.pkiPath);
        });

        it('Remove CA Cert', function() {
            certs.createCACert('CA Cert Test Removal', { basePath: global.pkiPath });
            certs.removeCACert('CA Cert Test Removal', global.pkiPath);
        });
    });

    describe('Server Tests', function() {
        it('Create Server Cert including Root CA in bundle', function() {
            certs.createServerCert('Server', 'ca-cert-2', false, {
                basePath: global.pkiPath,
                expired: false,
                rootCaName: 'CA Cert',
            });
        });

        it('Create Server Cert excluding Root CA in bundle', function() {
            certs.createServerCert('Server 2', 'ca-cert-2', false, {
                basePath: global.pkiPath,
                expired: false,
                rootCaName: null,
            });
        });

        it('Create Server Cert with start and expiration dates', function(done) {
            try {
                certs.createServerCert('Server Valid From and To', 'ca-cert-2', false, {
                    validFrom: '2050-01-01T00:00:00',
                    validTo: '2051-01-01T00:00:00',
                    basePath: global.pkiPath,
                    expired: false,
                    rootCaName: 'CA Cert',
                });
                const created = fs.pathExistsSync(
                    path.join(global.pkiPath, 'ca-cert-2/servers/server-valid-from-and-to/crt.pem')
                );
                expect(created).to.be.true;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('Create Server Cert with expiration before start should not be created', function(done) {
            try {
                certs.createServerCert('Server Valid To before From', 'ca-cert-2', false, {
                    validFrom: '2051-01-01T00:00:00',
                    validTo: '2050-01-01T00:00:00',
                    basePath: global.pkiPath,
                    expired: false,
                    rootCaName: 'CA Cert',
                });
                const created = fs.pathExistsSync(
                    path.join(global.pkiPath, 'ca-cert-2/servers/server-valid-to-before-from/crt.pem')
                );
                expect(created).to.be.false;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('Create Expired Server Cert', function() {
            certs.createServerCert('Server 3', 'ca-cert-2', false, {
                basePath: global.pkiPath,
                expired: true,
                rootCaName: 'CA Cert',
            });
        });

        it('Create Expired Server Cert for existing server', function() {
            certs.createServerCert('Server 2', 'ca-cert-2', false, {
                basePath: global.pkiPath,
                expired: true,
                rootCaName: null,
            });
        });

        it('List Server Certs', function() {
            certs.listServerCerts(global.pkiPath);
        });

        it('Remove Server Cert', function() {
            certs.createServerCert('Server Test Removal', 'ca-cert-2', false, {
                basePath: global.pkiPath,
                expired: false,
                rootCaName: 'CA Cert',
            });
            certs.removeServerCert('Server Test Removal', 'ca-cert-2', global.pkiPath);
        });
    });

    describe('User Tests', function() {
        const caName = 'User Tests CA';
        const caDir = 'user-tests-ca';

        before(function(done) {
            certs.createCACert(caName, { basePath: global.pkiPath });
            done();
        });

        after(function(done) {
            certs.removeCACert(caName, global.pkiPath);
            done();
        });

        it('Create User Cert', function(done) {
            certs.createUserCert('User 1', caName, { basePath: global.pkiPath, expired: false });
            const userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).to.contain('user-1');
            done();
        });

        it('Create User Cert with start and expiration dates', function(done) {
            try {
                certs.createUserCert('User Valid From and To', caName, {
                    validFrom: '2050-01-01T00:00:00',
                    validTo: '2051-01-01T00:00:00',
                    basePath: global.pkiPath,
                    expired: false,
                });
                const created = fs.pathExistsSync(
                    path.join(global.pkiPath, caDir, 'users/user-valid-from-and-to/crt.pem')
                );
                expect(created).to.be.true;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('Create User Cert with expiration before start should not be created', function(done) {
            try {
                certs.createUserCert('User Valid To before From', caName, {
                    validFrom: '2051-01-01T00:00:00',
                    validTo: '2050-01-01T00:00:00',
                    basePath: global.pkiPath,
                    expired: false,
                });
                const created = fs.pathExistsSync(
                    path.join(global.pkiPath, caDir, 'users/user-valid-to-before-from/crt.pem')
                );
                expect(created).to.be.false;
                done();
            } catch (e) {
                done(e);
            }
        });

        it('Create Expired User Cert', function(done) {
            certs.createUserCert('User 2', caName, { basePath: global.pkiPath, expired: true });
            const userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).to.contain('user-2');
            done();
        });

        it('Create Expired User Cert for existing User', function() {
            certs.createUserCert('User 1', caName, { basePath: global.pkiPath, expired: true });
        });

        it('List User Certs', function(done) {
            const userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).to.not.be.empty;
            done();
        });

        it('Create User Cert with rfc822 Subject Alternative', function(done) {
            certs.createUserCert('User 3', caName, {
                basePath: global.pkiPath,
                expired: false,
                subjectAltEmailNames: ['user3@example.org'],
            });
            const userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).to.contain('user-3');
            done();
        });

        it('Remove User Cert', function(done) {
            certs.createUserCert('User Test Removal', caName, {
                basePath: global.pkiPath,
                expired: false,
            });
            let userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).to.contain('user-test-removal');
            certs.removeUserCert('User Test Removal', caName, global.pkiPath);
            userCerts = certs.listUserCerts(global.pkiPath);
            expect(userCerts).not.to.contain('user-test-removal');
            done();
        });
    });

    describe('List Certs', function() {
        const originalTimeout = this.timeout;
        const newTimeout = originalTimeout * 4;

        after(function() {
            this.timeout(originalTimeout);
        });

        it('when CA, Servers, and Users Exist', function() {
            this.timeout(newTimeout); //this test creates 4 certs, so we allow 4x the time
            certs.createCACert('CA Cert List', { basePath: global.pkiPath });
            certs.createIntermediateCACert('CA Cert List 2', 'CA Cert List', { basePath: global.pkiPath });
            certs.createServerCert('Server List', 'ca-cert-list-2', false, {
                basePath: global.pkiPath,
                expired: false,
                rootCaName: 'CA Cert List',
            });
            certs.createUserCert('User List 1', 'ca-cert-list-2', {
                basePath: global.pkiPath,
                expired: false,
            });

            const list = certs.listCerts(global.pkiPath);
            expect(list.ca).to.not.be.null;

            const caCert = _.find(list.ca, { name: 'ca-cert-list' });
            expect(caCert).to.not.be.null;
            expect(caCert.servers).to.be.empty;
            expect(caCert.users).to.be.empty;

            const caCert2 = _.find(list.ca, { name: 'ca-cert-list-2' });
            expect(caCert2).to.not.be.null;
            expect(caCert2.servers).to.not.be.empty;
            expect(caCert2.users).to.not.be.empty;
        });

        it('when none exist', function() {
            fs.removeSync(global.pkiPath);

            const list = certs.listCerts(global.pkiPath);
            expect(list.ca).to.be.undefined;
        });
    });

    describe('Cert Database Tests', function() {
        before('', function() {
            certs.createCACert('ca cert db', { basePath: global.pkiPath });
        });

        it('Create Cert DB', function() {
            certs.createCertDatabase('ca cert db', { basePath: global.pkiPath });
        });
    });

    it('Normalize Name', function() {
        const name = certs.normalizeName('Test Name 3');
        expect(name).to.not.include(' ');
        expect(name).to.not.include('T');
        expect(name).to.not.include('N');
        expect(name).to.include('-');
        expect(name).to.equal('test-name-3');
    });
});
