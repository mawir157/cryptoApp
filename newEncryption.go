package main

import (
	"errors"

	"github.com/gotk3/gotk3/gtk"

	JMT "github.com/mawir157/jmtcrypto"
)

func newEncrypt(inBow, outBox *gtk.TextView, encIn Encoding, encOut Encoding,
	key1str string, ivStr string, cipher BCipher, modeOfOp CipherMode) error {
	text := get_text_from_tview(inBow)

	var byteStream []byte
	var err error
	switch encIn {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, true)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		return errors.New("unidentified plaintext encoding")
	}

	encryptedText := ""

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	byteStream, err = doNewEncryption(byteStream, key1str, ivStr, cipher, modeOfOp)

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	switch encOut {
	case Ascii:
		return errors.New("output encoding cannot be ascii")
	case Base64:
		encryptedText, err = JMT.ParseToBase64(byteStream)
	case Hex:
		encryptedText, err = JMT.ParseToHex(byteStream)
	default:
		return errors.New("unidentified ciphertext encoding")
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	set_text_in_tview(outBox, encryptedText)
	return nil
}

func newDecrypt(inBox, outBox *gtk.TextView, ptEnc Encoding, ctEnc Encoding,
	key1str string, cipher BCipher, modeOfOp CipherMode) error {

	text := get_text_from_tview(inBox)

	var byteStream []byte
	var err error
	switch ctEnc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, false)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		return errors.New("unidentified ciphertext encoding")
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	encryptedText := ""

	byteStream, err = doNewDecryption(byteStream, key1str, cipher, modeOfOp)

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	switch ptEnc {
	case Ascii:
		encryptedText, err = JMT.ParseToASCII(byteStream, true)
	case Base64:
		encryptedText, err = JMT.ParseToBase64(byteStream)
	case Hex:
		encryptedText, err = JMT.ParseToHex(byteStream)
	default:
		return errors.New("unidentified plaintext encoding")
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return err
	}

	set_text_in_tview(outBox, encryptedText)
	return nil
}

func doNewEncryption(msg []byte, key1str string, ivStr string, cipher BCipher,
	modeOfOp CipherMode) ([]byte, error) {
	key, err := JMT.ParseFromASCII(key1str, false)
	if err != nil {
		return []byte{}, errors.New("invalid key")
	}

	iv, err := JMT.ParseFromASCII(ivStr, false)
	if err != nil {
		return []byte{}, errors.New("invalid IV")
	}

	var bc JMT.BlockCipher
	switch cipher {
	case AES:
		bc = JMT.MakeAES(key)
	case Camellia:
		bc = JMT.MakeCamellia(key)
	case NULL:
		bc = JMT.MakeNULL(key)
	}

	out := []byte{}
	switch modeOfOp {
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

func doNewDecryption(msg []byte, key1str string, cipher BCipher,
	modeOfOp CipherMode) ([]byte, error) {
	key, err := JMT.ParseFromASCII(key1str, false)
	if err != nil {
		return []byte{}, errors.New("invalid key")
	}

	var bc JMT.BlockCipher
	switch cipher {
	case AES:
		bc = JMT.MakeAES(key)
	case Camellia:
		bc = JMT.MakeCamellia(key)
	case NULL:
		bc = JMT.MakeNULL(key)
	}

	out := []byte{}
	switch modeOfOp {
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
	}

	return out, err
}
