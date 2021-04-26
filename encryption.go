package main

import (
	"log"
)

import JMT "github.com/mawir157/jmtcrypto"
import JMTR "github.com/mawir157/jmtcrypto/rand"

func doEncryption(msg []byte, state *Config) []byte {
	key := JMT.BytesToWords(JMT.ParseFromAscii(state.key, false), false)

	var iv [4]JMT.Word
	temp := JMT.BytesToWords(JMT.ParseFromAscii(state.iv, false), false)
	copy(iv[:], temp)

	nonce := JMT.ParseFromAscii(state.nonce, false)
 	
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
  return out
}

func doDecryption(msg []byte, state *Config) []byte {
	key := JMT.BytesToWords(JMT.ParseFromAscii(state.key, false), false)

	var iv [4]JMT.Word
	temp := JMT.BytesToWords(JMT.ParseFromAscii(state.iv, false), false)
	copy(iv[:], temp)

	nonce := JMT.ParseFromAscii(state.nonce, false)
 	
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
	var err error
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
		log.Fatal("Failed to decrypt:", err)
  }
  return out
}