package main

import (
	"github.com/gotk3/gotk3/gtk"

	"fmt"
	"math/rand"
	"time"

	JMT "github.com/mawir157/jmtcrypto"
)

type HMACTabConfig struct {
	plaintextEnc Encoding
	hashtextEnc  Encoding
	key          string
	mode         HashMode
	widgets      map[string](HackWidget)
}

func (s *HMACTabConfig) addWidget(name string, w HackWidget) {
	s.widgets[name] = w
}

func onHMACKeyChanged(entry *gtk.Entry, s *HMACTabConfig) {
	s.key, _ = entry.GetText()
}

func onHMACKeyLoseFocus(entry *gtk.Entry, s *HMACTabConfig) {
	s.key, _ = entry.GetText()
}

func onHMAC(inBow, outBox *gtk.TextView, s *HMACTabConfig) {
	text := get_text_from_tview(inBow)

	var hs JMT.HashFunction
	byteStream := []byte{}
	var err error

	switch mode := s.mode; mode {
	case SHA256:
		hs = JMT.MakeSHA256()
	case SHA512:
		hs = JMT.MakeSHA512()
	default:
		fmt.Printf("Unidentified Hash function %d.\n", mode)
		hs = JMT.MakeSHA256()
	}

	switch enc := s.plaintextEnc; enc {
	case Ascii:
		byteStream, err = JMT.ParseFromASCII(text, false)
	case Base64:
		byteStream, err = JMT.ParseFromBase64(text, false)
	case Hex:
		byteStream, err = JMT.ParseFromHex(text, false)
	default:
		fmt.Printf("Unidentified Encoding (HASH IN) %d.\n", enc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	tempKey, _ := JMT.ParseFromASCII(s.key, false)
	byteStream = JMT.HMAC(tempKey, byteStream, hs)

	hashHex := ""
	switch enc := s.hashtextEnc; enc {
	case Base64:
		hashHex, err = JMT.ParseToBase64(byteStream)
	case Hex:
		hashHex, err = JMT.ParseToHex(byteStream)
	default:
		fmt.Printf("Unidentified Encoding (HASH OUT) %d.\n", enc)
	}

	if err != nil {
		set_text_in_tview(outBox, err.Error())
		return
	}

	set_text_in_tview(outBox, hashHex)
}

func onHMACInputEncodingChanged(cb *gtk.ComboBoxText, s *HMACTabConfig) {
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
}

func onHMACOutputEncodingChanged(cb *gtk.ComboBoxText, s *HMACTabConfig) {
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
}

func onHMACHashChanged(cb *gtk.ComboBoxText, s *HMACTabConfig) {
	switch enc := cb.GetActiveText(); enc {
	case "SHA256":
		s.mode = SHA256
	case "SHA512":
		s.mode = SHA512
	default:
		fmt.Printf("Unidentified Encoding (OUTPUT)%s.\n", enc)
		s.hashtextEnc = Ascii
	}
}

func hmacTab() (*gtk.Box, *HMACTabConfig, error) {
	widgets := make(map[string](HackWidget))
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	keySession := randString(16, r1)

	state := HMACTabConfig{plaintextEnc: Ascii, hashtextEnc: Base64, mode: SHA256,
		widgets: widgets, key: keySession}

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	plainText := add_text_box(main_box, LoremIpsum, "Input text")

	addHLine(main_box, 10)

	IOBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
	hmacKeyBox, _ := add_entry_box(IOBox, "Key", state.key, -1)
	hmacKeyBox.Connect("changed", func() {
		onHMACKeyChanged(hmacKeyBox, &state)
	})
	hmacKeyBox.Connect("focus_out_event", func() {
		onHMACKeyLoseFocus(hmacKeyBox, &state)
	})

	addHLine(IOBox, 10)

	hashes := []string{"SHA256", "SHA512"}
	hashCombo, _ := add_drop_down(IOBox, "Hash function: ", hashes, 0)

	addHLine(IOBox, 10)

	encdoings := []string{"ASCII", "base64", "hex"}
	inputEncCombo, _ := add_drop_down(IOBox, "Input Encoding: ", encdoings, 0)

	addHLine(IOBox, 10)

	outputEncCombo, _ := add_drop_down(IOBox, "Output Encoding: ", encdoings[1:], 0)

	addHLine(IOBox, 10)

	inputEncCombo.Connect("changed", func() {
		onHMACInputEncodingChanged(inputEncCombo, &state)
	})
	outputEncCombo.Connect("changed", func() {
		onHMACOutputEncodingChanged(outputEncCombo, &state)
	})

	btnHash := setup_btn("HMAC")
	IOBox.Add(btnHash)

	IOBox.SetHAlign(gtk.ALIGN_CENTER)

	main_box.PackStart(IOBox, false, true, 10)

	addHLine(main_box, 10)

	hashText := add_text_box(main_box, "HMAC will appear here", "HMAC")

	btnHash.Connect("clicked", func() {
		onHMAC(plainText, hashText, &state)
	})
	hashCombo.Connect("changed", func() {
		onHMACHashChanged(hashCombo, &state)
	}) // <- fix

	state.addWidget("btnHash", btnHash)
	state.addWidget("hashCombo", hashCombo)
	state.addWidget("inputEncCombo", inputEncCombo)
	state.addWidget("outputEncCombo", outputEncCombo)

	return main_box, &state, nil
}
