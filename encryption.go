package main

import (
	"errors"
	"fmt"

	"github.com/gotk3/gotk3/gtk"
)

import JMT "github.com/mawir157/jmtcrypto"
import JMTR "github.com/mawir157/jmtcrypto/rand"

func onEncrypt(inBow, outBox *gtk.TextView, s *Config) {

	text := get_text_from_tview(inBow)

	byteStream := []byte{}
	var err error
	switch enc := s.plaintextE; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromAscii(text, true)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.ciphertextE = Ascii
	}

	encryptedText := ""

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	byteStream, err = doEncryption(byteStream, s)

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	switch enc := s.ciphertextE; enc {
	case Ascii:
		fmt.Println("SHOULD NEVER GET HIT!")
	case Base64:
		encryptedText, err = JMT.ParseToBase64(byteStream)
	case Hex:
		encryptedText, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.ciphertextE = Ascii
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	set_text_in_tview(outBox, encryptedText)
	return
}

func onDecrypt(inBow, outBox *gtk.TextView, s *Config) {

	text := get_text_from_tview(inBow)

	byteStream := []byte{}
	var err error
	switch enc := s.ciphertextE; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromAscii(text, false)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		s.ciphertextE = Ascii
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	encryptedText := ""

	byteStream, err = doDecryption(byteStream, s)

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	switch enc := s.plaintextE; enc {
	case Ascii:
		encryptedText, err = JMT.ParseToAscii(byteStream, s.modeOfOp != CTR && s.modeOfOp != PRNG)
	case Base64:
		encryptedText, err = JMT.ParseToBase64(byteStream)
	case Hex:
		encryptedText, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.ciphertextE = Ascii
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	set_text_in_tview(outBox, encryptedText)
	return
}

func doEncryption(msg []byte, state *Config) ([]byte, error) {
	keyBytes, err := JMT.ParseFromAscii(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}
	key := JMT.BytesToWords(keyBytes, false)

	iv, err := JMT.ParseFromAscii(state.iv, false)
	if err != nil {
		return []byte{}, errors.New("Invalid IV")
	}

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
		case NULL:
			out = msg
	}
	return out, nil
}

func doDecryption(msg []byte, state *Config) ([]byte, error) {
	keyBytes, err := JMT.ParseFromAscii(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}
	key := JMT.BytesToWords(keyBytes, false)

	iv, err := JMT.ParseFromAscii(state.iv, false)
	if err != nil {
		return []byte{}, errors.New("Invalid IV")
	}

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
		case NULL:
			out = msg
	}

	if err != nil {
		return []byte{}, err
		// log.Fatal("Failed to decrypt:", err)
	}
	return out, err
}