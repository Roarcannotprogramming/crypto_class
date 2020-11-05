package main

import (
	"errors"
	"fmt"
	"mysrc/crypto"
	"os"
)

func main() {
	sbox := &[16]uint8{0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb}
	re_sbox := &[16]uint8{0x4, 0x8, 0x6, 0xa, 0x1, 0x3, 0x0, 0x5, 0xc, 0xe, 0xd, 0xf, 0x2, 0xb, 0x7, 0x9}
	ebox := &crypto.Ebox{Roundnb: 5, Sbox: sbox, Re_sbox: re_sbox}
	sm := PSboxMatrix(ebox)
	diff_in := []uint8{0x20, 0x00}
	pdiff_out, err := PRoundMatrix(ebox, sm, diff_in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(pdiff_out)
}

func PSboxMatrix(e *crypto.Ebox) (sm [16][16]uint8) {
	for diff := 0; diff < 16; diff++ {
		for i := 0; i < 16; i++ {
			index := e.Sbox[i] ^ e.Sbox[i^diff]
			sm[diff][index]++
		}
	}
	return
}

func PRoundMatrix(e *crypto.Ebox, sm [16][16]uint8, diff_in []uint8) (pdiff_out map[uint32]float64, err error) {
	if len(diff_in) != 2 {
		err = errors.New("Error: PSboxMatrix check failed")
		return
	}
	diff_in0 := diff_in[0] & 0xf
	diff_in1 := diff_in[0] >> 4
	diff_in2 := diff_in[1] & 0xf
	diff_in3 := diff_in[1] >> 4
	pdiff_out = make(map[uint32]float64)
	for i := uint32(0); i < 16; i++ {
		for j := uint32(0); j < 16; j++ {
			for k := uint32(0); k < 16; k++ {
				for l := uint32(0); l < 16; l++ {
					key := l | (k << 4) | (j << 8) | (i << 12)
					k0 := (key & 0x1) | ((key & 0x10) >> 3) | ((key & 0x100) >> 6) | ((key & 0x1000) >> 9)
					k0 |= ((key & 0x2) << 3) | (key & 0x20) | ((key & 0x200) >> 3) | ((key & 0x2000) >> 6)
					k0 |= ((key & 0x4) << 6) | ((key & 0x40) << 3) | (key & 0x400) | ((key & 0x4000) >> 3)
					k0 |= ((key & 0x8) << 9) | ((key & 0x80) << 6) | ((key & 0x800) << 3) | (key & 0x8000)

					v_cnt := uint32(sm[diff_in0][l]) * uint32(sm[diff_in1][k]) * uint32(sm[diff_in2][j]) * uint32(sm[diff_in3][i])
					if v_cnt != 0 {
						pdiff_out[k0] = float64(v_cnt) / float64(0x10000)
					}
				}
			}
		}
	}
	return
}

func PDiffPath(e *crypto.Ebox, sm [16][16]uint8, diff []uint8) {

}
