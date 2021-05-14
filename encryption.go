package main

import (
	"errors"
	"fmt"

	"github.com/gotk3/gotk3/gtk"
)

import JMT "github.com/mawir157/jmtcrypto"
// import JMTR "github.com/mawir157/jmtcrypto/rand"

func onEncrypt(inBow, outBox *gtk.TextView, s *Config) {
	text := get_text_from_tview(inBow)

	needPad := (s.modeOfOp != CTR) && (s.modeOfOp != PRNG)
	byteStream := []byte{}
	var err error
	switch enc := s.plaintextE; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, needPad)
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
		byteStream, err = JMT.ParseFromASCII(text, false)
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

	needPad := (s.modeOfOp != CTR) && (s.modeOfOp != PRNG)

	switch enc := s.plaintextE; enc {
	case Ascii:
		encryptedText, err = JMT.ParseToASCII(byteStream, needPad)
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
	key, err := JMT.ParseFromASCII(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}

	iv, err := JMT.ParseFromASCII(state.iv, false)
	if err != nil {
		return []byte{}, errors.New("Invalid IV")
	}

	nonce, err := JMT.ParseFromASCII(state.nonce, false)
 	if err != nil {
		return []byte{}, errors.New("Invalid Nonce")
	}

	var bc JMT.BlockCipher
	switch state.cipher {
		case AES:
			bc = JMT.MakeAES(key)
		case Camellia:
			bc = JMT.MakeCamellia(key)
		case NULL:
			bc = JMT.MakeNULL(key)
	}
	var rng JMT.PRNG
	switch state.rng {
		case Mersenne:
			rng = JMT.Mersenne19937Init()
		case PCG:
			rng = JMT.PCGInit()
	}

	out := []byte{}
	switch state.modeOfOp {
		case ECB:
			out = JMT.ECBEncrypt(bc, msg)
		case CBC:
			out = JMT.CBCEncrypt(bc, iv, msg)
			out = append(iv, out...)
		case PCB:
			out = JMT.PCBCEncrypt(bc, iv, msg)
			out = append(iv, out...)
		case OFB:
			out = JMT.OFBEncrypt(bc, iv, msg)
			out = append(iv, out...)
		case CTR:
			out = JMT.CTREncrypt(bc, nonce, msg)
		case CFB:
			out = JMT.CFBEncrypt(bc, iv, msg)
			out = append(iv, out...)
		case PRNG:
			_, out = JMT.PRNGStreamEncode(state.seed, rng, msg)
	}
	return out, nil
}

func doDecryption(msg []byte, state *Config) ([]byte, error) {
	key, err := JMT.ParseFromASCII(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
	}

	nonce, err := JMT.ParseFromASCII(state.nonce, false)
 	if err != nil {
		return []byte{}, errors.New("Invalid Nonce")
	}
 	
	var bc JMT.BlockCipher
	switch state.cipher {
		case AES:
			bc = JMT.MakeAES(key)
		case Camellia:
			bc = JMT.MakeCamellia(key)
		case NULL:
			bc = JMT.MakeNULL(key)
	}

	var rng JMT.PRNG
	switch state.rng {
		case Mersenne:
			rng = JMT.Mersenne19937Init()
		case PCG:
			rng = JMT.PCGInit()
	}

	out := []byte{}
	switch state.modeOfOp {
		case ECB:
			out, err = JMT.ECBDecrypt(bc, msg)
		case CBC:
			out, err = JMT.CBCDecrypt(bc, msg[:bc.BlockSize()], msg[bc.BlockSize():])
		case PCB:
			out, err = JMT.PCBCDecrypt(bc, msg[:bc.BlockSize()], msg[bc.BlockSize():])
		case OFB:
			out, err = JMT.OFBDecrypt(bc, msg[:bc.BlockSize()], msg[bc.BlockSize():])
		case CTR:
			out, err = JMT.CTRDecrypt(bc, nonce, msg)
		case CFB:
			out, err = JMT.CFBDecrypt(bc, msg[:bc.BlockSize()], msg[bc.BlockSize():])
		case PRNG:
			out = JMT.PRNGStreamDecode(state.seed, rng, msg)
	}

	if err != nil {
		return []byte{}, err
		// log.Fatal("Failed to decrypt:", err)
	}
	return out, err
}