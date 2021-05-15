package main

import (
	// "encoding/hex"
	// "encoding/base64"

	// "github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"fmt"
	// "math/rand"
  // "time"
)

import JMT "github.com/mawir157/jmtcrypto"

type HashTabConfig struct {
	plaintextEnc Encoding
	hashtextEnc  Encoding
	mode         HashMode
	widgets      map[string](HackWidget)
}

func (s *HashTabConfig) addWidget(name string, w HackWidget) {
	s.widgets[name] = w
}

func onHash(inBow, outBox *gtk.TextView, s *HashTabConfig) {
	text := get_text_from_tview(inBow)

	hs := JMT.MakeSHA256()
	byteStream := []byte{}
	var err error

	switch enc := s.plaintextEnc; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, false)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		fmt.Printf("Unidentified Encoding (HASH IN)%s.\n", enc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	byteStream = hs.Hash(byteStream)

	hashHex := ""
	switch enc := s.hashtextEnc; enc {
	case Base64:
		hashHex, err = JMT.ParseToBase64(byteStream)
	case Hex:
		hashHex, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding (HASH OUT)%s.\n", enc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	set_text_in_tview(outBox, hashHex)
	return
}

func onInputEncodingChanged(cb *gtk.ComboBoxText, s *HashTabConfig) {
	switch enc := cb.GetActiveText(); enc {
	case "ASCII":
		s.plaintextEnc = Ascii
	case "base64":
		s.plaintextEnc = Base64
	case "hex":
		s.plaintextEnc = Hex
	default:
		fmt.Printf("Unidentified Encoding (INPUT)%s.\n", enc)
		s.plaintextEnc = Ascii
	}

	return
}

func onOutputEncodingChanged(cb *gtk.ComboBoxText, s *HashTabConfig) {
	switch enc := cb.GetActiveText(); enc {
	case "ASCII":
		s.hashtextEnc = Ascii
	case "base64":
		s.hashtextEnc = Base64
	case "hex":
		s.hashtextEnc = Hex
	default:
		fmt.Printf("Unidentified Encoding (OUTPUT)%s.\n", enc)
		s.hashtextEnc = Ascii
	}

	return
}

func hashTab() (*gtk.Box, *HashTabConfig, error) {
	widgets := make(map[string](HackWidget))

	state := HashTabConfig{plaintextEnc:Ascii, hashtextEnc:Base64, mode:SHA256,
	                       widgets:widgets}

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
		plainText := add_text_box(main_box, LoremIpsum, "Input text")

		IOBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
		hashes := []string{"SHA256", "SHA512"}
		hashCombo, _ := add_drop_down(IOBox, "Hash function: ", hashes, 0)

		addHLine(main_box, 10)

		btnHash := setup_btn("Hash")
		IOBox.Add(btnHash)

		encdoings := []string{"ASCII", "base64", "hex"}
		inputEncCombo, _ := add_drop_down(IOBox, "Input Encoding: ", encdoings, 0)
		outputEncCombo, _ := add_drop_down(IOBox, "Output Encoding: ", encdoings[1:], 0)
		inputEncCombo.Connect("changed", onInputEncodingChanged, &state)
		outputEncCombo.Connect("changed", onOutputEncodingChanged, &state)
		// IOBox.Add(inputEncCombo)
		// IOBox.Add(outputEncCombo)

		main_box.PackStart(IOBox, true, true, 0)

		addHLine(main_box, 10)

		hashText := add_text_box(main_box, "Hash will appear here", "Hash")

		btnHash.Connect("clicked", func() {
			onHash(plainText, hashText, &state)
		})
		hashCombo.Connect("changed", onPrimitiveChanged, &state)

		state.addWidget("btnHash", btnHash)
		state.addWidget("hashCombo", hashCombo)
		state.addWidget("inputEncCombo", inputEncCombo)
		state.addWidget("outputEncCombo", outputEncCombo)

		return main_box, &state, nil
}