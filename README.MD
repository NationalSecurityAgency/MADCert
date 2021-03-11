# MADCert

Use MADCert to create root and intermediate Certificate Authorities, issue user and server certificates, etc for testing purposes.

MADCert is a cross-platform tool that does not require OpenSSL or any other programs to be installed in the Operating System.

## Prerequisites

-  You will need Node.js installed on your operating system. For Linux and Mac OS X, we recommend using [nvm - Node Version Manager](https://github.com/nvm-sh/nvm). For Windows, we recommend using [nvm-windows](https://github.com/coreybutler/nvm-windows).

## Installation

To add MADCert to your project:

    npm install madcert

## Usage

    npx madcert <command> <arguments> [options]

## Environment

-   `MADCERT_LH_SUBJECT_ALT_DNS_NAME` - Only used when creating a localhost server certificate (`--localhost true`). When generating a localhost server certificate, MADCert will add a subject alternative DNS name to the certificate. This environment variable can be used to specify the subject alternative DNS name that will be added. If this environment variable is not set, then the host name will be used.

## Commands, Arguments, and Options

When you run MADCert help (using `npx madcert --help`), it will display all of the commands, arguments, and options.

### Arguments

-   `name` Name is used for the name of the directory under which PKI files are created. If the `--common-name` option is not used then `name` will also be used for the Common Name in the certificate subject.
-   `ca_name` CA name is used to identify the Certificate Authority to use when creating or removing users and servers.
-   `root_ca_name` When creating an intermediate Certificate Authority, `root_ca_name` identifies the root CA that issues the intermediate CA's certificate.

### Options

The MADCert options are grouped in the help output by the commands that they can be used with.

-   Creation Options - these options can be used with any of the commands that create PKI files for CAs, servers, and users
-   User Creation Options - these options can be used with the `user-create` command
-   Server Creation Options - these options can be used with the `server-create` command
-   Options - these options are not specific to any particular command

## Certificate Storage Location

By default, the certs created by MADCert will be placed under a "pki" folder in the current working directory. MADCert commands also have the `--path` or `-p` option to specify a top-level path where the certs will be stored. It is important that all of the certs are placed under the same top-level folder, so either run MADCert from within the same directory each time or always provide the same path option when calling the MADCert commands.

## Examples

-   Create a Certificate Authority (CA)

        npx madcert ca-create test-root-ca --common-name "Test Root CA" --org "Some Organization" --country "US"

-   Create an Intermediate CA (Root CA must exist)

        npx madcert ca-create test-ca test-root-ca --common-name "Test CA" --org-unit "orgA" --org-unit "A123" --org "Some Organization" --country "US"

-   Create a Server Certificate (CA must exist)

        npx madcert server-create test-server test-ca --common-name "test.server" --org-unit "S333" --org "Some Organization" --country "US" --subject-alt-ip "123.45.23.111"

-   Create a localhost Server Certificate (CA must exist)

        npx madcert server-create localhost test-ca --localhost true --common-name "localhost" --org-unit "D009" --org-unit "DoD" --org "U.S. Government" --country "US"

        Note: A subject alternative name is automatically added to the generated certificate.  See ENVIRONMENT above.

-   Create a User Certificate with CN=test-user (CA must exist)

        npx madcert user-create test-user test-ca --org-unit "SECURITY" --org-unit "A456" --org "Some Organization" --country "US"

-   Create a User Certificate CN=Alice Example (CA must exist)

        npx madcert user-create test-user test-ca --common-name "Alice Example" --org-unit "SECURITY" --org-unit "A456" --org "Some Organization" --country "US"
