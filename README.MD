# MADCert

Use MADCert to create root and intermediate Certificate Authorities, issue user and server certificates, etc for testing purposes.

MADCert is a cross-platform tool that consists of a certificate generator, a file system certificate manager, and a command line interface.

MADCert does not require openssl or any other programs to be installed in the Operating System.

Both Node.js and CLI exmples are provided below.


## Usage

### Node.js Examples

To add MADCert to your project:

    npm install madcert

    var madcert = require("madcert")

-   Create a Certificate Authority (CA)

        madcert.createCACert("Test Root CA", {validFrom: "2019-08-08", validTo: "2024-08-09"})

-   Create an Intermediate CA (Root CA must exist)

        madcert.createIntermediateCACert("Test CA","rootCA", {validFrom: "2019-08-08", validTo: "2024-08-09"});

-   Create a Server Certificate (CA must exist)

        madcert.createServerCert("Test Server", "test-ca", false, {validFrom: "2019-08-08", validTo: "2024-08-09"});

-   Create a localhost Server Certificate (CA must exist)

        madcert.createServerCert("localhost", "test-ca", true, {validFrom: "2019-08-08", validTo: "2024-08-09"});

        Note: A subject alternative name is automatically added to the generated certificate.  See ENVIRONMENT above.

-   Create a User Certificate with CN=test-user (CA must exist)

        madcert.createUserCert("test-user", "test-ca", {commonName: "test-user", organizationalUnits: ["SECURITY", "A456"], organizations: ["Some Organization"], country: "US", validFrom: "2019-08-08", validTo: "2024-08-09"});

-   Create a User Certificate CN=Alice Example (CA must exist)

        madcert.createUserCert("Alice Example", "test-ca", {commonName: "Alice Example", organizationalUnits: ["SECURITY", "A456"], organizations: ["Some Organization"], country: "US", validFrom: "2019-08-08", validTo: "2024-08-09"});

-   List CA Certificates

        madcert.listCACerts();

-   List Server Cerficates

        madcert.listServerCerts();

-   List User Certificates

        madcert.listUserCerts();

-   Remove a CA Certificate

        madcert.removeCACert("test-root-ca");

-   Remove a Server Certificate

        madcert.removeServerCert("test-server", "test-ca");

-   Remove a User Certificate

        madcert.removeUserCert("test-user", "test-ca");

-   Retrieve a CA Certificate as JSON

        madcert.caCertToJSON("test-root-ca");

-   Retrieve a Server Certificate as JSON

        madcert.serverCertToJSON("test-server", "test-ca");

-   Retrieve a User Certificate as JSON

        madcert.userCertToJSON("test-user", "test-ca");

-  Convert name to a File Path Friendly Name

        madcert.normalizeName("Test 123");
        > 'test-123'

### Additional Node.js Options

#### Certificate Storage Location

By default, the certs created by MADCert will be placed under a "pki" folder in the current working directory. MADCert commands also have the `basePath` option to specify a top-level path where the certs will be stored. It is important that all of the certs are placed under the same top-level folder, so either run MADCert from within the same location each time or always provide the same basepath option when calling the MADCert commands.

- Example Specifying the Certificate Storage Location (available on all certificate related commands)

        madcert.createCACert("Test Root CA", {validFrom: "2019-08-08", validTo: "2024-08-09", basePath: "/some/path"})


### CLI Examples

-   General Syntax

        npx madcert <command> <arguments> [options]

-   Help

        npx madcert --help

    The MADCert options are grouped in the help output by the commands that they can be used with.

    -   Creation Options - these options can be used with any of the commands that create PKI files for CAs, servers, and users
    -   User Creation Options - these options can be used with the `user-create` command
    -   Server Creation Options - these options can be used with the `server-create` command
    -   Print Options - these options can be used with the `ca-print`, `server-print`, and `user-print` commands
    -   Options - these options are not specific to any particular command


-   Create a Certificate Authority (CA)

        npx madcert ca-create test-root-ca --common-name "Test Root CA" --org "Some Organization" --country "US"

-   Create an Intermediate CA (Root CA must exist)

        npx madcert ca-intermediate-create test-ca test-root-ca --common-name "Test CA" --org-unit "orgA" --org-unit "A123" --org "Some Organization" --country "US"

-   Create a Server Certificate (CA must exist)

        npx madcert server-create test-server test-ca --common-name "test.server" --org-unit "S333" --org "Some Organization" --country "US" --subject-alt-ip "123.45.23.111"

-   Create a localhost Server Certificate (CA must exist)

        npx madcert server-create localhost test-ca --localhost true --common-name "localhost" --org-unit "D009" --org-unit "DoD" --org "U.S. Government" --country "US"

        Note: A subject alternative name is automatically added to the generated certificate.  See ENVIRONMENT above.

-   Create a User Certificate with CN=test-user (CA must exist)

        npx madcert user-create test-user test-ca --org-unit "SECURITY" --org-unit "A456" --org "Some Organization" --country "US"

-   Create a User Certificate CN=Alice Example (CA must exist)

        npx madcert user-create test-user test-ca --common-name "Alice Example" --org-unit "SECURITY" --org-unit "A456" --org "Some Organization" --country "US"

-   List CA Certificates

        npx madcert ca-list

-   List Server Cerficates

        npx madcert server-list

-   List User Certificates

        npx madcert user-list

-   Remove a CA Certificate

        npx madcert ca-remove test-ca

-   Remove a Server Certificate

        npx madcert server-remove test-server test-ca

-   Remove a User Certificate

        npx madcert user-remove test-user test-ca

-   Print a CA Certificate

        npx madcert ca-print test-ca

-   Print a Server Certificate

        npx madcert server-print test-server test-ca

-   Print a User Certificate

        npx madcert user-print test-user test-ca

### Additional CLI Options

#### Certificate Storage Location

By default, the certs created by MADCert will be placed under a "pki" folder in the current working directory. MADCert commands also have the `--path` or `-p` option to specify a top-level path where the certs will be stored. It is important that all of the certs are placed under the same top-level folder, so either run MADCert from within the same directory each time or always provide the same path option when calling the MADCert commands.

#### Environment

-   `MADCERT_LH_SUBJECT_ALT_DNS_NAME` - Only used when creating a localhost server certificate (`--localhost true`). When generating a localhost server certificate, MADCert will add a subject alternative DNS name to the certificate. This environment variable can be used to specify the subject alternative DNS name that will be added. If this environment variable is not set, then the host name will be used.

#### Arguments


|                    | Alias | Type    | Default Value | Description |
| :---               | :----:| :----:  |    :----:     |        ---: |
| `name`             |       | String  |               | Name is used for the name of the directory under which PKI files are created. If the `--common-name` option is not used then `name` will also be used for the Common Name in the certificate subject.   |
| `ca-name`          |       | String  |               | CA name is used to identify the Certificate Authority to use when creating or removing users and servers.      |
| `root_ca-name`     | `-r`  | String  |               | When creating an intermediate Certificate Authority, `root_ca_name` identifies the root CA that issues the intermediate CA's certificate.
| `path`             | `-p`  | String  | '/pki'        | Base path for pki |
| `common-name`      | `-n`  | String  |               | Common Name in the Distinguished Name |
| `country`          | `-c`  | String  |               | Country |
| `locality`         |       | String  |               | Locality|
| `state`            | `-st` | String  |               | State|
| `expired`          | `-e`  | Boolean |               | Create an expired certificate |
| `org`              | `-o`  | Array   |               | Organization name. This option can be specified multiple times|
| `org-unit`         | `-u`  | Array   |               | Organizational unit name. This option can be specified multiple times.|
| `password`         | `-w`  | String  | 'changeme'    | Certificate password |
| `subject-alt-dns`  | `-d`  | Array   |               | Create certificate with DNS subject alternative name. This option can be specified multiple times.|
| `subject-alt-ip`   | `-i`  | Array   |               | Create certificate with IP subject alternative name. This option can be specified multiple times.      |
| `subject-alt-email`| `-m`  | Array   |               | Create certificate with rfc822/email subject alternative name. This option can be specified multiple times.|
| `valid-from`       | `-f`  | Date    |               | Valid from date in ISO 8601 format |
| `valid-to`         | `-t`  | Date    |               | Valid to date in ISO 8601 format|
