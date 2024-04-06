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

$ bundle exec ruby exe/echspec --help
```

## Usage

```sh-session
Usage: echspec [options] hostname
    -f, --file FILE                  path to ECHConfigs PEM file       (default resolve ECHConfigs via DNS)
    -p, --port VALUE                 server port number                (default 443)
    -n, --not-force-compliant-hpke   not force compliant ECHConfig HPKE cipher suite
    -v, --verbose                    verbose mode; prints message stack if raised an error
```

```sh-session
$ bundle exec ruby exe/echspec -f fixtures/echconfigs.pem -p 4433 localhost
```

```sh-session
$ bundle exec ruby exe/echspec crypto.cloudflare.com
```

## License

`echspec` is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
