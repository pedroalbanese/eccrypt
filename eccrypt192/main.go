// ECC 192-bit Asymmetric Encryption Scheme
package eccrypt192

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type eccrypterCipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand,0)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher,0)
}

func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:24])
	y := new(big.Int).SetBytes(data[24:48])
	hash := data[48:80]
	cipherText := data[80:]
	return asn1.Marshal(eccrypterCipher{x, y, hash, cipherText})
}

func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher eccrypterCipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 24 {
		x = append(zeroByteSlice()[:24-n], x...)
	}
	if n := len(y); n < 24 {
		y = append(zeroByteSlice()[:24-n], y...)
	}
	c := []byte{}
	c = append(c, x...)          
	c = append(c, y...)          
	c = append(c, hash...)       
	c = append(c, cipherText...) 
	return append([]byte{0x04}, c...), nil
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

func Encrypt(pub *PublicKey, data []byte, random io.Reader,mode int) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 24 {
			x1Buf = append(zeroByteSlice()[:24-n], x1Buf...)
		}
		if n := len(y1Buf); n < 24 {
			y1Buf = append(zeroByteSlice()[:24-n], y1Buf...)
		}
		if n := len(x2Buf); n < 24 {
			x2Buf = append(zeroByteSlice()[:24-n], x2Buf...)
		}
		if n := len(y2Buf); n < 24 {
			y2Buf = append(zeroByteSlice()[:24-n], y2Buf...)
		}
		c = append(c, x1Buf...)
		c = append(c, y1Buf...)
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)

		Sum256 := func(msg []byte) []byte {
			res := sha256.New()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}

		h := Sum256(tm)
		c = append(c, h...)
		ct, ok := kdf(length, x2Buf, y2Buf)
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[80+i] ^= data[i]
		}
		switch mode{
	
		case 0:
			return append([]byte{0x04}, c...), nil
		case 1:
			c1 := make([]byte, 48)
			c2 := make([]byte, len(c) - 80)
			c3 := make([]byte, 24)
			copy(c1, c[:48])
			copy(c3, c[48:80])
			copy(c2, c[80:])
			ciphertext := []byte{}
			ciphertext = append(ciphertext, c1...)
			ciphertext = append(ciphertext, c2...)
			ciphertext = append(ciphertext, c3...)
			return append([]byte{0x04}, ciphertext...), nil
    	default:
			return append([]byte{0x04}, c...), nil
	}
}
}

func Decrypt(priv *PrivateKey, data []byte,mode int) ([]byte, error) {
	switch mode {
	case 0:
		data = data[1:]
	case 1:
		data = data[1:]
		c1 := make([]byte, 48)
		c2 := make([]byte, len(data) - 80)
		c3 := make([]byte, 24)
		copy(c1, data[:48])//x1,y1
		copy(c2, data[48:len(data) - 24])
		copy(c3, data[len(data) - 24:])
		c := []byte{}
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	length := len(data) - 80
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:24])
	y := new(big.Int).SetBytes(data[24:48])
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 24 {
		x2Buf = append(zeroByteSlice()[:24-n], x2Buf...)
	}
	if n := len(y2Buf); n < 24 {
		y2Buf = append(zeroByteSlice()[:24-n], y2Buf...)
	}
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+80]
	}
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)

	Sum256 := func(msg []byte) []byte {
		res := sha256.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	h := Sum256(tm)
	if bytes.Compare(h, data[48:80]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte
	ct := 1
	h := sha256.New()
	for i, j := 0, (length+23)/24; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%24 != 0 {
			c = append(c, hash[:length%24]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
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
