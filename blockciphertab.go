package main

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"fmt"
	"math/rand"
	"time"
)

type Config struct {
	plaintextE  Encoding
	ciphertextE Encoding
	cipher      BCipher
	modeOfOp    CipherMode
	key         string
	iv          string
	valid       bool
	widgets     map[string](HackWidget)
}

func (s *Config) addWidget(name string, w HackWidget) {
	s.widgets[name] = w
}

func onKeyChanged(entry *gtk.Entry, s *Config) {
	s.key, _ = entry.GetText()
}

func onKeyLoseFocus(entry *gtk.Entry, event *gdk.Event, s *Config) {
	name := "Key"
	required := 16

	key, _ := entry.GetText()
	if len(key) != 16 {
		s.valid = false
		title := fmt.Sprintf("%s length warning", name)
		message := fmt.Sprintf("Warning!\n %s must be exactly\n%d bytes.", name, required)

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()
		return
	} else {
		s.valid = true
	}

	return
}

func onIvChanged(entry *gtk.Entry, s *Config) {
	s.iv, _ = entry.GetText()
}

func onIVLoseFocus(entry *gtk.Entry, event *gdk.Event, s *Config) {
	name := "IV"
	required := 16
	v, _ := entry.GetText()

	if len(v) != required {
		s.valid = false
		title := fmt.Sprintf("%s length warning", name)
		message := fmt.Sprintf("Warning!\n %s must be exactly\n%d bytes.", name, required)

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()
	} else {
		s.valid = true
	}

	return
}

func validateButton(btn *gtk.Button, s *Config) {
	btn.SetSensitive(s.valid)

	return
}

func onPTEncodingChanged(cb *gtk.ComboBoxText, s *Config) {
	switch enc := cb.GetActiveText(); enc {
	case "ascii":
		s.plaintextE = Ascii
	case "base64":
		s.plaintextE = Base64
	case "hex":
		s.plaintextE = Hex
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.plaintextE = Ascii
	}

	return
}

func onCTEncodingChanged(cb *gtk.ComboBoxText, s *Config) {
	switch enc := cb.GetActiveText(); enc {
	case "ascii":
		s.ciphertextE = Ascii
	case "base64":
		s.ciphertextE = Base64
	case "hex":
		s.ciphertextE = Hex
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.ciphertextE = Ascii
	}

	return
}

func onPrimitiveChanged(cb *gtk.ComboBoxText, s *Config) {
	switch enc := cb.GetActiveText(); enc {
	case "AES":
		s.cipher = AES
	case "Camellia":
		s.cipher = Camellia
	case "NULL":
		s.cipher = NULL
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.cipher = AES
	}

	return
}

func isValidText(s string, enc Encoding) bool {
	switch enc {
	case Ascii:
		return true // can always parse ascii
	case Base64:
		_, err := hex.DecodeString(s)
		return (err == nil)
	case Hex:
		_, err := base64.StdEncoding.DecodeString(s)
		return (err == nil)
	default:
		return false
	}
}

func onModeChanged(cb *gtk.ComboBoxText, s *Config) {
	switch enc := cb.GetActiveText(); enc {
	case "ECB":
		s.modeOfOp = ECB
		updateCipherMode(false, true, false, false, true, false, s)
	case "CBC":
		s.modeOfOp = CBC
		updateCipherMode(false, true, true, false, true, false, s)
	case "PCB":
		s.modeOfOp = PCB
		updateCipherMode(false, true, true, false, true, false, s)
	case "OFB":
		s.modeOfOp = OFB
		updateCipherMode(false, true, true, false, true, false, s)
	case "CTR":
		s.modeOfOp = CTR
		updateCipherMode(false, true, false, true, true, false, s)
	case "CFB":
		s.modeOfOp = CFB
		updateCipherMode(false, true, true, false, true, false, s)
	case "PRNG stream":
		s.modeOfOp = PRNG
		updateCipherMode(true, false, false, false, false, true, s)
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.modeOfOp = ECB
	}

	return
}

// 0 - Block Cipher, 1 - Stream Cipher
func updateCipherMode(seed, key, iv, nonce, prim, rng bool, s *Config) {
	// set everything to false
	// for k, _ := range s.widgets {
	//		 s.widgets[k].SetSensitive(false)
	// }
	s.widgets["modeCombo"].SetSensitive(true)

	if seed {
		s.widgets["seedBox"].SetSensitive(true)
		s.widgets["seedLabel"].SetSensitive(true)
	}

	if key {
		s.widgets["keyBox"].SetSensitive(true)
		s.widgets["keyLabel"].SetSensitive(true)
	}

	if iv {
		s.widgets["ivBox"].SetSensitive(true)
		s.widgets["ivLabel"].SetSensitive(true)
	}

	if prim {
		s.widgets["primCombo"].SetSensitive(true)
		s.widgets["primLabel"].SetSensitive(true)
	}

	return
}

func blockCipherTab() (*gtk.Box, *Config, error) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	keySession := randString(16, r1)
	ivSession := randString(16, r1)

	widgets := make(map[string](HackWidget))

	state := Config{plaintextE: Ascii, ciphertextE: Base64, cipher: AES,
		modeOfOp: ECB, key: keySession, iv: ivSession,
		valid: true, widgets: widgets}

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	////////////////////////////////////////////////////////////////////////////////
	text_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
	text_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	plainText := add_text_box(text_box_lhs, TextMessage, "PlainText")

	encdoings := []string{"ascii", "base64", "hex"}
	ptEncoding, _ := add_drop_down(text_box_lhs, "Encoding: ", encdoings, 0)
	ptEncoding.Connect("changed", func() {
		onPTEncodingChanged(ptEncoding, &state)
	})

	text_box.PackStart(text_box_lhs, true, true, 0)
	addVLine(text_box, 10)

	text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	cipherText := add_text_box(text_box_rhs, "Cipher text here!", "CipherText")

	ctEncoding, _ := add_drop_down(text_box_rhs, "Encoding: ", encdoings[1:], 0)
	ctEncoding.Connect("changed", func() {
		onCTEncodingChanged(ctEncoding, &state)
	})

	text_box.PackStart(text_box_rhs, true, true, 0)

	main_box.PackStart(text_box, true, true, 0)
	addHLine(main_box, 10)
	////////////////////////////////////////////////////////////////////////////////
	mode_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	mode_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	blockCiphers := []string{"AES", "Camellia", "NULL"}
	primCombo, primLabel := add_drop_down(mode_box_lhs, "Block cipher: ", blockCiphers, 0)
	modes := []string{"ECB", "CBC", "PCB", "OFB", "CFB"}
	modeCombo, _ := add_drop_down(mode_box_lhs, "Cipher mode: ", modes, 0)

	primCombo.Connect("changed", func() {
		onPrimitiveChanged(primCombo, &state)
	})
	modeCombo.Connect("changed", func() {
		onModeChanged(modeCombo, &state)
	})
	state.addWidget("modeCombo", modeCombo)
	state.addWidget("primCombo", primCombo)
	state.addWidget("primLabel", primLabel)

	mode_box.PackStart(mode_box_lhs, true, true, 0)
	addVLine(mode_box, 10)

	mode_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	keyBox, keyLabel := add_entry_box(mode_box_rhs, "Key", state.key, 16)
	keyBox.Connect("changed", func() {
		onKeyChanged(keyBox, &state)
	})

	keyBox.Connect("focus_out_event", func() {
		onKeyLoseFocus(keyBox, nil, &state)
	})
	state.addWidget("keyBox", keyBox)
	state.addWidget("keyLabel", keyLabel)

	ivBox, ivLabel := add_entry_box(mode_box_rhs, "IV", state.iv, 16)

	ivBox.Connect("changed", func() {
		onIvChanged(ivBox, &state)
	})

	ivBox.Connect("focus_out_event", func() {
		onIVLoseFocus(ivBox, nil, &state)
	})
	state.addWidget("ivBox", ivBox)
	state.addWidget("ivLabel", ivLabel)

	mode_box.PackStart(mode_box_rhs, true, true, 0)
	main_box.PackStart(mode_box, true, true, 0)
	addHLine(main_box, 10)
	////////////////////////////////////////////////////////////////////////////////
	do_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
	addHLine(do_box, 10)

	io_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	btnOpen := setup_btn("Open")
	io_box.Add(btnOpen)

	btnSave := setup_btn("Save")
	io_box.Add(btnSave)

	io_box.SetHAlign(gtk.ALIGN_CENTER)

	do_box.Add(io_box)
	addHLine(do_box, 10)

	endecrypt_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	btnEncrypt := setup_btn("Encrypt")
	btnEncrypt.Connect("clicked", func() {
		onEncrypt(plainText, cipherText, &state)
	})
	endecrypt_box.Add(btnEncrypt)
	state.addWidget("btnEncrypt", btnEncrypt)

	btnDecrypt := setup_btn("Decrypt")
	btnDecrypt.Connect("clicked", func() {
		onDecrypt(cipherText, plainText, &state)
	})
	endecrypt_box.Add(btnDecrypt)
	state.addWidget("btnDecrypt", btnDecrypt)

	endecrypt_box.SetHAlign(gtk.ALIGN_CENTER)

	do_box.Add(endecrypt_box)
	addHLine(do_box, 10)

	close_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	btnClose := setup_btn("Close")
	// btnClose.Connect("clicked", func() {
	// 	win.Close()
	// })
	close_box.Add(btnClose)

	close_box.SetHAlign(gtk.ALIGN_CENTER)

	do_box.Add(close_box)
	addHLine(do_box, 10)

	do_box.SetHAlign(gtk.ALIGN_CENTER)

	main_box.PackStart(do_box, false, true, 10)
	addHLine(main_box, 10)

	return main_box, &state, nil
}
