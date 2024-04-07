# echspec

[![Actions Status](https://github.com/thekuwayama/echspec/actions/workflows/ci.yml/badge.svg)](https://github.com/thekuwayama/echspec/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://raw.githubusercontent.com/thekuwayama/echspec/main/LICENSE.txt)

`echspec` is a conformance testing tool for ECH implementation.

- https://datatracker.ietf.org/doc/draft-ietf-tls-esni/

## Install

You can run it the following:

```sh-session
$ gem install bundler

$ bundle install
```

## Usage

```sh-session
$ bundle exec ruby exe/echspec --help
Usage: echspec [options] hostname
    -f, --file FILE                  path to ECHConfigs PEM file       (default resolve ECHConfigs via DNS)
    -p, --port VALUE                 server port number                (default 443)
    -n, --not-force-compliant-hpke   not force compliant ECHConfig HPKE cipher suite
    -v, --verbose                    verbose mode; prints message stack if raised an error
```

You can run it the following:

```sh-session
$ bundle exec ruby exe/echspec crypto.cloudflare.com
	MUST implement the following HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM. [9]
	MUST abort with an "illegal_parameter" alert, if EncodedClientHelloInner is padded with non-zero values [5.1-9]
	MUST abort with an "illegal_parameter" alert, if ECHClientHello.type is not a valid ECHClientHelloType in ClientHelloInner [7-2.3.1]
	MUST abort with an "illegal_parameter" alert, if ECHClientHello.type is not a valid ECHClientHelloType in ClientHelloOuter [7-2.3.1]
	MUST abort with an "illegal_parameter" alert, if ClientHelloInner offers TLS 1.2 or below [7.1-10]
	MUST include the "encrypted_client_hello" extension in its EncryptedExtensions with the "retry_configs" field set to one or more ECHConfig [7.1-13.2.1]
	MUST abort with a "missing_extension" alert, if 2nd ClientHelloOuter does not contains the "encrypted_client_hello" extension [7.1.1-2]
	MUST abort with an "illegal_parameter" alert, if 2nd ClientHelloOuter "encrypted_client_hello" enc is empty [7.1.1-2]
	MUST abort with a "decrypt_error" alert, if fails to decrypt 2nd ClientHelloOuter [7.1.1-5]
```

By default, `echspec` retrieves ECHConfigs via HTTPS records. By using the `-f, --file FILE` option, you can specify an ECHConfig pem file. If you need to test the server on localhost, you can run it the following:

```sh-session
$ bundle exec ruby exe/echspec -f fixtures/echconfigs.pem -p 4433 localhost
```

By default, `echspec` uses the following HPKE cipher suite

- KEM
  - DHKEM(X25519, HKDF-SHA256)
- KDF
  - HKDF-SHA256
- AEAD
  - AES-128-GCM

By using the `-n, --not-force-compliant-hpke`, you can not enforce the HPKE cipher suite.

```sh-session
$ bundle exec ruby exe/echspec -f fixtures/echconfigs.pem -p 4433 -n localhost
```

## License

`echspec` is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
