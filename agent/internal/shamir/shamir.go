package shamir

import (
	"crypto/rand"
	"errors"
)

func mul(a, b byte) byte {
	var product byte
	for b > 0 {
		if b&1 == 1 {
			product ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return product
}

func inverse(a byte) byte {
	result := byte(1)
	for range 254 {
		result = mul(result, a)
	}
	return result
}

func Split(secret []byte, holders int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("the secret is empty")
	}
	if holders < 1 || holders > 255 {
		return nil, errors.New("pieces go to 1 to 255 holders")
	}
	if holders == 1 {
		return [][]byte{append([]byte{0}, secret...)}, nil
	}
	slope := make([]byte, len(secret))
	rand.Read(slope)
	pieces := make([][]byte, holders)
	for i := range pieces {
		x := byte(i + 1)
		piece := make([]byte, len(secret)+1)
		piece[0] = x
		for j, value := range secret {
			piece[j+1] = value ^ mul(slope[j], x)
		}
		pieces[i] = piece
	}
	return pieces, nil
}

func Combine(pieces [][]byte) ([]byte, error) {
	if len(pieces) == 1 && len(pieces[0]) > 1 && pieces[0][0] == 0 {
		return append([]byte(nil), pieces[0][1:]...), nil
	}
	if len(pieces) < 2 {
		return nil, errors.New("two pieces are needed")
	}
	first, second := pieces[0], pieces[1]
	if len(first) < 2 || len(first) != len(second) {
		return nil, errors.New("the pieces do not belong together")
	}
	x1, x2 := first[0], second[0]
	if x1 == 0 || x2 == 0 || x1 == x2 {
		return nil, errors.New("the pieces do not belong together")
	}
	scale := inverse(x1 ^ x2)
	secret := make([]byte, len(first)-1)
	for j := range secret {
		secret[j] = mul(mul(first[j+1], x2)^mul(second[j+1], x1), scale)
	}
	return secret, nil
}
