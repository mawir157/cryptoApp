package main

import (
	"errors"
	// "log"
)

import JMT "github.com/mawir157/jmtcrypto"
import JMTR "github.com/mawir157/jmtcrypto/rand"

func doEncryption(msg []byte, state *Config) ([]byte, error) {
	keyBytes, err := JMT.ParseFromAscii(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}
	key := JMT.BytesToWords(keyBytes, false)

	var iv [4]JMT.Word
	ivBytes, err := JMT.ParseFromAscii(state.iv, false)
	if err != nil {
		return []byte{}, errors.New("Invalid IV")
	}
	temp := JMT.BytesToWords(ivBytes, false)
	copy(iv[:], temp)

	nonce, err := JMT.ParseFromAscii(state.nonce, false)
 	if err != nil {
		return []byte{}, errors.New("Invalid Nonce")
	}

	var bc JMT.BlockCipher
	switch state.cipher {
		case AES:
			bc = JMT.MakeAES(key)
	}

	var rng JMT.PRNG
	switch state.rng {
		case Mersenne:
			rng = JMTR.Mersenne19937Init()
		case PCG:
			rng = JMTR.PCGInit()
	}

	out := []byte{}
	switch state.modeOfOp {
		case ECB:
			out = JMT.ECBEncrypt(bc, msg)
		case CBC:
			out = JMT.CBCEncrypt(bc, iv, msg)
		case PCB:
			out = JMT.PCBCEncrypt(bc, iv, msg)
		case OFB:
			out = JMT.OFBEncrypt(bc, iv, msg)
		case CTR:
			out = JMT.CTREncrypt(bc, nonce, msg)
		case CFB:
			out = JMT.CFBEncrypt(bc, iv, msg)
		case PRNG:
			_, out = JMT.PRNGStreamEncode(state.seed, rng, msg)
	}
	return out, nil
}

func doDecryption(msg []byte, state *Config) ([]byte, error) {
	keyBytes, err := JMT.ParseFromAscii(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}
	key := JMT.BytesToWords(keyBytes, false)

	var iv [4]JMT.Word
	ivBytes, err := JMT.ParseFromAscii(state.iv, false)
	if err != nil {
		return []byte{}, errors.New("Invalid IV")
	}
	temp := JMT.BytesToWords(ivBytes, false)
	copy(iv[:], temp)

	nonce, err := JMT.ParseFromAscii(state.nonce, false)
 	if err != nil {
		return []byte{}, errors.New("Invalid Nonce")
	}
 	
	var bc JMT.BlockCipher
	switch state.cipher {
		case AES:
			bc = JMT.MakeAES(key)
	}

	var rng JMT.PRNG
	switch state.rng {
		case Mersenne:
			rng = JMTR.Mersenne19937Init()
		case PCG:
			rng = JMTR.PCGInit()
	}

	out := []byte{}
	switch state.modeOfOp {
		case ECB:
			out, err = JMT.ECBDecrypt(bc, msg)
		case CBC:
			out, err = JMT.CBCDecrypt(bc, iv, msg)
		case PCB:
			out, err = JMT.PCBCDecrypt(bc, iv, msg)
		case OFB:
			out, err = JMT.OFBDecrypt(bc, iv, msg)
		case CTR:
			out, err = JMT.CTRDecrypt(bc, nonce, msg)
		case CFB:
			out, err = JMT.CFBDecrypt(bc, iv, msg)
		case PRNG:
			out = JMT.PRNGStreamDecode(state.seed, rng, msg)
	}

	if err != nil {
		return []byte{}, err
		// log.Fatal("Failed to decrypt:", err)
	}
	return out, err
}