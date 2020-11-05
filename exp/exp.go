package main

import (
	"errors"
	"fmt"
	"mysrc/crypto"
	"os"
)

func main() {
	key := [][2]uint8{{0x12, 0x34}, {0x56, 0x78}, {0x9a, 0xbc}, {0xde, 0xf0}, {0xde, 0xad}, {0xca, 0xfe}}

	sbox := &[16]uint8{0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb}
	re_sbox := &[16]uint8{0x4, 0x8, 0x6, 0xa, 0x1, 0x3, 0x0, 0x5, 0xc, 0xe, 0xd, 0xf, 0x2, 0xb, 0x7, 0x9}
	ebox := &crypto.Ebox{Roundnb: 5, Sbox: sbox, Re_sbox: re_sbox}

	diff := []uint8{0x00, 0x00}
	guess_key := []uint8{0x00, 0x00}
	guess_diff := []uint8{0x00, 0x00}

	// Recover the last round key
	prob_key := uint8(0)
	most_vote := uint64(0)
	rcvd_key := []uint8{0x00, 0x00}
	fmt.Println("======= 0~3 bits =======")
	diff[0] = 0x20
	guess_diff[0] = 0x02
	for i := uint8(0); i < 16; i++ {
		guess_key[0] = i
		vote, err := DiffRound(ebox, diff, key, guess_key, guess_diff)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if vote > most_vote {
			most_vote = vote
			prob_key = i
		}
		fmt.Printf("vote: %v, guess key: %#x\n", vote, guess_key)
	}
	rcvd_key[0] |= prob_key
	fmt.Printf("most vote: %v, probable key: %#x\n", most_vote, prob_key)

	most_vote = 0
	fmt.Println("======= 4~7 bits =======")
	diff[0] = 0x20
	guess_diff[0] = 0x20
	for i := uint8(0); i < 16; i++ {
		guess_key[0] = i * 0x10
		vote, err := DiffRound(ebox, diff, key, guess_key, guess_diff)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if vote > most_vote {
			most_vote = vote
			prob_key = i
		}

		fmt.Printf("vote: %v, guess key: %#x\n", vote, guess_key)
	}
	rcvd_key[0] |= (prob_key << 4)
	fmt.Printf("most vote: %v, probable key: %#x\n", most_vote, prob_key)

	most_vote = 0
	fmt.Println("======= 8~11 bits =======")
	diff[0] = 0x20
	diff[1] = 0x00
	guess_diff[0] = 0x00
	guess_diff[1] = 0x02
	guess_key[0] = 0x00
	for i := uint8(0); i < 16; i++ {
		guess_key[1] = i
		vote, err := DiffRound(ebox, diff, key, guess_key, guess_diff)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if vote > most_vote {
			most_vote = vote
			prob_key = i
		}

		fmt.Printf("vote: %v, guess key: %#x\n", vote, guess_key)
	}
	rcvd_key[1] |= prob_key
	fmt.Printf("most vote: %v, probable key: %#x\n", most_vote, prob_key)

	most_vote = 0
	fmt.Println("======= 12~15 bits =======")
	diff[0] = 0x00
	diff[1] = 0x20
	guess_diff[0] = 0x00
	guess_diff[1] = 0x20
	guess_key[0] = 0x00
	for i := uint8(0); i < 16; i++ {
		guess_key[1] = i * 0x10
		vote, err := DiffRound(ebox, diff, key, guess_key, guess_diff)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if vote > most_vote {
			most_vote = vote
			prob_key = i
		}

		fmt.Printf("vote: %v, guess key: %#x\n", vote, guess_key)
	}
	rcvd_key[1] |= (prob_key << 4)
	fmt.Printf("most vote: %v, probable key: %#x\n", most_vote, prob_key)

	fmt.Printf("%#x\n", rcvd_key)

	// Recover the second last key

}

func DiffRound(e *crypto.Ebox, diff []uint8, key [][2]uint8, guess_key []uint8, guess_diff []uint8) (vote uint64, err error) {
	if len(diff) != 2 || len(guess_key) != 2 || len(guess_diff) != 2 {
		err = errors.New("Error: DiffRound check faild")
		return
	}

	var cipher1 []uint8
	var cipher2 []uint8
	msg1 := make([]uint8, 2, 2)
	msg2 := make([]uint8, 2, 2)

	for hb := 0; hb < 256; hb++ {
		msg1[1] = uint8(hb)
		for lb := 0; lb < 256; lb++ {
			msg1[0] = uint8(lb)
			msg2[0] = msg1[0] ^ diff[0]
			msg2[1] = msg1[1] ^ diff[1]

			cipher1, err = e.Encrypt(msg1, key)
			if err != nil {
				return
			}
			cipher2, err = e.Encrypt(msg2, key)
			if err != nil {
				return
			}

			q_cipher1 := make([]uint8, 2, 2)
			q_cipher2 := make([]uint8, 2, 2)

			q_cipher1[0] = cipher1[0] ^ guess_key[0]
			q_cipher1[1] = cipher1[1] ^ guess_key[1]
			q_cipher1[0] = e.Re_sbox[q_cipher1[0]&0xf] | (e.Re_sbox[q_cipher1[0]>>4] << 4)
			q_cipher1[1] = e.Re_sbox[q_cipher1[1]&0xf] | (e.Re_sbox[q_cipher1[1]>>4] << 4)

			q_cipher2[0] = cipher2[0] ^ guess_key[0]
			q_cipher2[1] = cipher2[1] ^ guess_key[1]
			q_cipher2[0] = e.Re_sbox[q_cipher2[0]&0xf] | (e.Re_sbox[q_cipher2[0]>>4] << 4)
			q_cipher2[1] = e.Re_sbox[q_cipher2[1]&0xf] | (e.Re_sbox[q_cipher2[1]>>4] << 4)

			if guess_diff[0] == q_cipher1[0]^q_cipher2[0] && guess_diff[1] == q_cipher1[1]^q_cipher2[1] {
				vote++
			}
		}
	}

	return
}

/*----------------------------------------------------------------













remained area for coding
















---------------------------------------------------------------*/
