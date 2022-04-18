// Command-line ECDSA Asymmetric Crypter
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/pedroalbanese/eccrypt"
)

var (
	dec = flag.Bool("dec", false, "Decrypt with Private key.")
	enc = flag.Bool("enc", false, "Encrypt with Public key.")
	key = flag.String("key", "", "Private/Public key.")
	gen = flag.Bool("gen", false, "Generate keypair.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(2)
	}

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = elliptic.P256()

	if *gen {
		privatekey = new(ecdsa.PrivateKey)
		privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if len(WritePrivateKeyToHex(privatekey)) != 64 {
			log.Fatal("Private key too short!")
			os.Exit(1)
		}

		pubkey = privatekey.PublicKey
		fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
		fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
		os.Exit(0)
	}

	if *enc {
		public, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := eccrypt.EncryptAsn1(public, []byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
		os.Exit(0)
	}

	if *dec {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str, _ := hex.DecodeString(string(scanner))
		plaintxt, err := eccrypt.DecryptAsn1(private, []byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
		os.Exit(0)
	}
}

func ReadPrivateKeyFromHex(Dhex string) (*eccrypt.PrivateKey, error) {
	c := elliptic.P256()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func WritePrivateKeyToHex(key *ecdsa.PrivateKey) string {
	d := key.D.Bytes()
	if n := len(d); n < 32 {
		d = append(zeroByteSlice()[:64-n], d...)
	}
	c := []byte{}
	c = append(c, d...)
	return hex.EncodeToString(c)
}

func ReadPublicKeyFromHex(Qhex string) (*eccrypt.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(eccrypt.PublicKey)
	pub.Curve = elliptic.P256()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

func WritePublicKeyToHex(key *ecdsa.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	return hex.EncodeToString(c)
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
