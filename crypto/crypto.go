package crypto

import (
	"errors"
)

type Ebox struct {
	Roundnb uint64 // number of rounds
	Sbox    *[16]uint8
	Re_sbox *[16]uint8
}

/*
func main() {
	msg := [2]uint8{0xca, 0xfe}
	key := [][2]uint8{{0x12, 0x34}, {0x56, 0x78}, {0x9a, 0xbc}, {0xde, 0xf0}, {0xde, 0xad}, {0xbe, 0xef}}

	Sbox := &[16]uint8{0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb}
	Re_sbox := &[16]uint8{0x4, 0x8, 0x6, 0xa, 0x1, 0x3, 0x0, 0x5, 0xc, 0xe, 0xd, 0xf, 0x2, 0xb, 0x7, 0x9}
	ebox := &Ebox{Roundnb: 5, Sbox: Sbox, Re_sbox: Re_sbox}

	inp := msg[:]

	outp, err := ebox.Encrypt(inp, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	inp, err = ebox.Decrypt(outp, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Printf("Decrypted message: %#x\n", inp)
	fmt.Printf("Key: %#x\n", key)
	fmt.Printf("Original Massage: %#x\n", msg)
	fmt.Printf("Encrypted Cipher: %#x\n", outp)

}
*/

func (e Ebox) encRound(inp []uint8) (outp []uint8, err error) {
	if inp == nil || e.Sbox == nil {
		err = errors.New("Error: encRound check failed")
		return
	}
	inp_in4bit := make([]uint8, 4, 4)
	for i := uint64(0); i < 2; i++ {
		inp_in4bit[2*i] = inp[i] & 0xf
		inp_in4bit[2*i+1] = inp[i] >> 4
	}
	outp = make([]uint8, 2, 2)
	out_in4bit := make([]uint8, 4, 4)
	out_in4bit[0] = (e.Sbox[inp_in4bit[0]] & 1) | ((e.Sbox[inp_in4bit[1]] & 1) << 1) | ((e.Sbox[inp_in4bit[2]] & 1) << 2) | ((e.Sbox[inp_in4bit[3]] & 1) << 3)
	out_in4bit[1] = ((e.Sbox[inp_in4bit[0]] & 2) >> 1) | (e.Sbox[inp_in4bit[1]] & 2) | ((e.Sbox[inp_in4bit[2]] & 2) << 1) | ((e.Sbox[inp_in4bit[3]] & 2) << 2)
	out_in4bit[2] = ((e.Sbox[inp_in4bit[0]] & 4) >> 2) | ((e.Sbox[inp_in4bit[1]] & 4) >> 1) | (e.Sbox[inp_in4bit[2]] & 4) | ((e.Sbox[inp_in4bit[3]] & 4) << 1)
	out_in4bit[3] = ((e.Sbox[inp_in4bit[0]] & 8) >> 3) | ((e.Sbox[inp_in4bit[1]] & 8) >> 2) | ((e.Sbox[inp_in4bit[2]] & 8) >> 1) | (e.Sbox[inp_in4bit[3]] & 8)
	outp[0] = out_in4bit[0] | out_in4bit[1]<<4
	outp[1] = out_in4bit[2] | out_in4bit[3]<<4
	return
}

func (e Ebox) decRound(inp []uint8) (outp []uint8, err error) {
	if inp == nil || e.Re_sbox == nil {
		err = errors.New("Error: decRound check failed")
		return
	}
	inp_in4bit := make([]uint8, 4, 4)
	inp_in4bit[0] = inp[0] & 0xf
	inp_in4bit[1] = inp[0] >> 4
	inp_in4bit[2] = inp[1] & 0xf
	inp_in4bit[3] = inp[1] >> 4
	out_in4bit := make([]uint8, 4, 4)
	out_in4bit[0] = e.Re_sbox[(inp_in4bit[0]&1)|((inp_in4bit[1]&1)<<1)|((inp_in4bit[2]&1)<<2)|((inp_in4bit[3]&1)<<3)]
	out_in4bit[1] = e.Re_sbox[((inp_in4bit[0]&2)>>1)|(inp_in4bit[1]&2)|((inp_in4bit[2]&2)<<1)|((inp_in4bit[3]&2)<<2)]
	out_in4bit[2] = e.Re_sbox[((inp_in4bit[0]&4)>>2)|((inp_in4bit[1]&4)>>1)|(inp_in4bit[2]&4)|((inp_in4bit[3]&4)<<1)]
	out_in4bit[3] = e.Re_sbox[((inp_in4bit[0]&8)>>3)|((inp_in4bit[1]&8)>>2)|((inp_in4bit[2]&8)>>1)|(inp_in4bit[3]&8)]
	outp = make([]uint8, 2, 2)
	outp[0] = out_in4bit[0] | out_in4bit[1]<<4
	outp[1] = out_in4bit[2] | out_in4bit[3]<<4
	return
}

func (e Ebox) Encrypt(msg []uint8, key [][2]uint8) (cipher []uint8, err error) {
	if len(msg) != 2 || uint64(len(key)) != e.Roundnb+1 {
		err = errors.New("Error: Encrypt check failed")
		return
	}

	cipher = make([]uint8, 2, 2)
	if nb := copy(cipher, msg); nb != 2 {
		err = errors.New("Error: Encrypt copy failed")
		return
	}

	for i := uint64(0); i < e.Roundnb-1; i++ {
		cipher[0] = cipher[0] ^ key[i][0]
		cipher[1] = cipher[1] ^ key[i][1]
		cipher, err = e.encRound(cipher)
		if err != nil {
			return
		}
	}

	// the last round
	cipher[0] = cipher[0] ^ key[e.Roundnb-1][0]
	cipher[1] = cipher[1] ^ key[e.Roundnb-1][1]
	cipher[0] = e.Sbox[(cipher[0]&0xf)] | (e.Sbox[cipher[0]>>4] << 4)
	cipher[1] = e.Sbox[(cipher[1]&0xf)] | (e.Sbox[cipher[1]>>4] << 4)
	cipher[0] = cipher[0] ^ key[e.Roundnb][0]
	cipher[1] = cipher[1] ^ key[e.Roundnb][1]

	return
}

func (e Ebox) Decrypt(cipher []uint8, key [][2]uint8) (msg []uint8, err error) {
	if len(cipher) != 2 || uint64(len(key)) != e.Roundnb+1 {
		err = errors.New("Error: Decrypt check failed")
		return
	}

	msg = make([]uint8, 2, 2)
	if nb := copy(msg, cipher); nb != 2 {
		err = errors.New("Error: Decrypt copy failed")
		return
	}

	msg[0] = msg[0] ^ key[e.Roundnb][0]
	msg[1] = msg[1] ^ key[e.Roundnb][1]
	msg[0] = e.Re_sbox[msg[0]&0xf] | (e.Re_sbox[msg[0]>>4] << 4)
	msg[1] = e.Re_sbox[msg[1]&0xf] | (e.Re_sbox[msg[1]>>4] << 4)
	msg[0] = msg[0] ^ key[e.Roundnb-1][0]
	msg[1] = msg[1] ^ key[e.Roundnb-1][1]

	for i := e.Roundnb - 2; i >= 0 && i < e.Roundnb; i-- {
		msg, err = e.decRound(msg)
		if err != nil {
			return
		}
		msg[0] = msg[0] ^ key[i][0]
		msg[1] = msg[1] ^ key[i][1]
	}
	return
}
