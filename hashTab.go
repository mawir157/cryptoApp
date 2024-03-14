package main

import (
	"github.com/gotk3/gotk3/gtk"

	"fmt"

	JMT "github.com/mawir157/jmtcrypto"
)

func onHash(inBow, outBox *gtk.TextView, plaintextEnc Encoding,
	hashtextEnc Encoding, mode HashMode) {
	text := get_text_from_tview(inBow)

	byteStream := []byte{}
	var err error

	switch plaintextEnc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, false)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		fmt.Printf("Unidentified Encoding (HASH IN) %d.\n", plaintextEnc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	switch mode {
	case SHA256:
		hs := JMT.MakeSHA256()
		byteStream = hs.Hash(byteStream)
	case SHA512:
		hs := JMT.MakeSHA512()
		byteStream = hs.Hash(byteStream)
	default:
		fmt.Printf("Unidentified Hash function %d.\n", mode)
		hs := JMT.MakeSHA256()
		byteStream = hs.Hash(byteStream)
	}

	hashHex := ""
	switch hashtextEnc {
	case Base64:
		hashHex, err = JMT.ParseToBase64(byteStream)
	case Hex:
		hashHex, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding (HASH OUT) %d.\n", hashtextEnc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	set_text_in_tview(outBox, hashHex)
}

func onInputEncodingChanged(cb *gtk.ComboBoxText, plaintextEnc *Encoding) {
	switch enc := cb.GetActiveText(); enc {
	case "ASCII":
		*plaintextEnc = Ascii
	case "base64":
		*plaintextEnc = Base64
	case "hex":
		*plaintextEnc = Hex
	default:
		fmt.Printf("Unidentified Encoding (INPUT)%s.\n", enc)
		*plaintextEnc = Ascii
	}
}

func onOutputEncodingChanged(cb *gtk.ComboBoxText, hashtextEnc *Encoding) {
	switch enc := cb.GetActiveText(); enc {
	case "ASCII":
		*hashtextEnc = Ascii
	case "base64":
		*hashtextEnc = Base64
	case "hex":
		*hashtextEnc = Hex
	default:
		fmt.Printf("Unidentified Encoding (OUTPUT)%s.\n", enc)
		*hashtextEnc = Ascii
	}
}

func onHashChanged(cb *gtk.ComboBoxText, mode *HashMode) {
	switch hash := cb.GetActiveText(); hash {
	case "SHA256":
		*mode = SHA256
	case "SHA512":
		*mode = SHA512
	default:
		fmt.Printf("Unidentified Hash Function %s.\n", hash)
		*mode = SHA256
	}
}

func hashTab() (*gtk.Box, error) {
	plainTextE := Ascii
	ciphertextE := Base64
	hash := SHA256

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	plainText := add_text_box(main_box, LoremIpsum, "Input text")

	addHLine(main_box, 10)

	IOBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
	hashes := []string{"SHA256", "SHA512"}
	hashCombo, _ := add_drop_down(IOBox, "Hash function: ", hashes, 0)

	addHLine(IOBox, 10)

	encdoings := []string{"ASCII", "base64", "hex"}
	inputEncCombo, _ := add_drop_down(IOBox, "Input Encoding: ", encdoings, 0)

	addHLine(IOBox, 10)

	outputEncCombo, _ := add_drop_down(IOBox, "Output Encoding: ", encdoings[1:], 0)

	addHLine(IOBox, 10)

	inputEncCombo.Connect("changed", func() {
		onInputEncodingChanged(inputEncCombo, &plainTextE)
	})
	outputEncCombo.Connect("changed", func() {
		onOutputEncodingChanged(outputEncCombo, &ciphertextE)
	})
	hashCombo.Connect("changed", func() {
		onHashChanged(hashCombo, &hash)
	})

	btnHash := setup_btn("Hash")
	IOBox.Add(btnHash)

	IOBox.SetHAlign(gtk.ALIGN_CENTER)

	main_box.PackStart(IOBox, false, true, 10)

	addHLine(main_box, 10)

	hashText := add_text_box(main_box, "Hash will appear here", "Hash")

	btnHash.Connect("clicked", func() {
		onHash(plainText, hashText, plainTextE, ciphertextE, hash)
	})

	return main_box, nil
}
