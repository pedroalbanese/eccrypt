# EC Crypt 160/192/256/512-bit
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/eccrypt/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/eccrypt?status.png)](http://godoc.org/github.com/pedroalbanese/eccrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/eccrypt)](https://goreportcard.com/report/github.com/pedroalbanese/eccrypt)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/eccrypt)](https://github.com/pedroalbanese/eccrypt/releases)

### Elliptic curve-based Asymmetric Encryption Scheme

## CMD Examples:
```sh
./ecdsacrypter -gen
./ecdsacrypter -enc -key $pubkey < plaintext.ext > ciphertext.ext 
./ecdsacrypter -dec -key $prvkey < ciphertext.ext 
```

## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2022 ALBANESE Research Lab.
