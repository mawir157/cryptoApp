package main

import (
	"errors"
	"fmt"

	"github.com/gotk3/gotk3/gtk"

	JMT "github.com/mawir157/jmtcrypto"
)

// import JMTR "github.com/mawir157/jmtcrypto/rand"

func onEncrypt(inBow, outBox *gtk.TextView, s *Config) {
	text := get_text_from_tview(inBow)

	byteStream := []byte{}
	var err error
	switch enc := s.plaintextE; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, true)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		fmt.Printf("Unidentified Encoding %d.\n", enc)
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
		fmt.Printf("Unidentified Encoding %d.\n", enc)
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

	switch enc := s.plaintextE; enc {
	case Ascii:
		encryptedText, err = JMT.ParseToASCII(byteStream, true)
	case Base64:
		encryptedText, err = JMT.ParseToBase64(byteStream)
	case Hex:
		encryptedText, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding %d.\n", enc)
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

	var bc JMT.BlockCipher
	switch state.cipher {
	case AES:
		bc = JMT.MakeAES(key)
	case Camellia:
		bc = JMT.MakeCamellia(key)
	case NULL:
		bc = JMT.MakeNULL(key)
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
	case CFB:
		out = JMT.CFBEncrypt(bc, iv, msg)
		out = append(iv, out...)
	}
	return out, nil
}

func doDecryption(msg []byte, state *Config) ([]byte, error) {
	key, err := JMT.ParseFromASCII(state.key, false)
	if err != nil {
		return []byte{}, errors.New("Invalid Key")
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
	case CFB:
		out, err = JMT.CFBDecrypt(bc, msg[:bc.BlockSize()], msg[bc.BlockSize():])
	}

	if err != nil {
		return []byte{}, err
		// log.Fatal("Failed to decrypt:", err)
	}
	return out, err
}
