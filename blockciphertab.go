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

func onKeyChanged(entry *gtk.Entry, key *string) {
	*key, _ = entry.GetText()
}

func onKeyLoseFocus(entry *gtk.Entry, event *gdk.Event, valid *bool) {
	name := "Key"
	required := 16

	key, _ := entry.GetText()
	if len(key) != 16 {
		*valid = false
		title := fmt.Sprintf("%s length warning", name)
		message := fmt.Sprintf("Warning!\n %s must be exactly\n%d bytes.", name, required)

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()
		return
	} else {
		*valid = true
	}
}

func onIvChanged(entry *gtk.Entry, iv *string) {
	*iv, _ = entry.GetText()
}

func onIVLoseFocus(entry *gtk.Entry, event *gdk.Event, valid *bool) {
	name := "IV"
	required := 16
	v, _ := entry.GetText()

	if len(v) != required {
		*valid = false
		title := fmt.Sprintf("%s length warning", name)
		message := fmt.Sprintf("Warning!\n %s must be exactly\n%d bytes.", name, required)

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()
	} else {
		*valid = true
	}
}

func validateButton(btn *gtk.Button, valid *bool) {
	btn.SetSensitive(*valid)
}

func onPTEncodingChanged(cb *gtk.ComboBoxText, plaintextE *Encoding) {
	switch enc := cb.GetActiveText(); enc {
	case "ascii":
		*plaintextE = Ascii
	case "base64":
		*plaintextE = Base64
	case "hex":
		*plaintextE = Hex
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		*plaintextE = Ascii
	}
}

func onCTEncodingChanged(cb *gtk.ComboBoxText, ciphertextE *Encoding) {
	switch enc := cb.GetActiveText(); enc {
	case "ascii":
		*ciphertextE = Ascii
	case "base64":
		*ciphertextE = Base64
	case "hex":
		*ciphertextE = Hex
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		*ciphertextE = Ascii
	}
}

func onPrimitiveChanged(cb *gtk.ComboBoxText, cipher *BCipher) {
	switch enc := cb.GetActiveText(); enc {
	case "AES":
		*cipher = AES
	case "Camellia":
		*cipher = Camellia
	case "NULL":
		*cipher = NULL
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		*cipher = AES
	}
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

// TODO Sort out activating fields
func onModeChanged(cb *gtk.ComboBoxText, modeOfOp *CipherMode, btns map[string]HackWidget) {
	switch enc := cb.GetActiveText(); enc {
	case "ECB":
		*modeOfOp = ECB
		// updateCipherMode(false, true, false, false, true, false, s)
	case "CBC":
		*modeOfOp = CBC
		// updateCipherMode(false, true, true, false, true, false, s)
	case "PCB":
		*modeOfOp = PCB
		// updateCipherMode(false, true, true, false, true, false, s)
	case "OFB":
		*modeOfOp = OFB
		// updateCipherMode(false, true, true, false, true, false, s)
	case "CTR":
		*modeOfOp = CTR
		// updateCipherMode(false, true, false, true, true, false, s)
	case "CFB":
		*modeOfOp = CFB
		// updateCipherMode(false, true, true, false, true, false, s)
	case "PRNG stream":
		*modeOfOp = PRNG
		// updateCipherMode(true, false, false, false, false, true, s)
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		*modeOfOp = ECB
	}
}

func blockCipherTab() (*gtk.Box, error) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	keySession := randString(16, r1)
	ivSession := randString(16, r1)
	plaintextE := Ascii
	ciphertextE := Base64
	cipher := AES
	modeOfOp := ECB
	valid := true

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	////////////////////////////////////////////////////////////////////////////////
	text_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
	text_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	plainText := add_text_box(text_box_lhs, TextMessage, "PlainText")

	encdoings := []string{"ascii", "base64", "hex"}
	ptEncoding, _ := add_drop_down(text_box_lhs, "Encoding: ", encdoings, 0)
	ptEncoding.Connect("changed", func() {
		onPTEncodingChanged(ptEncoding, &plaintextE)
	})

	text_box.PackStart(text_box_lhs, true, true, 0)
	addVLine(text_box, 10)

	text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	cipherText := add_text_box(text_box_rhs, "Cipher text here!", "CipherText")

	ctEncoding, _ := add_drop_down(text_box_rhs, "Encoding: ", encdoings[1:], 0)
	ctEncoding.Connect("changed", func() {
		onCTEncodingChanged(ctEncoding, &ciphertextE)
	})

	text_box.PackStart(text_box_rhs, true, true, 0)

	main_box.PackStart(text_box, true, true, 0)
	addHLine(main_box, 10)
	////////////////////////////////////////////////////////////////////////////////
	mode_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	mode_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	blockCiphers := []string{"AES", "Camellia", "NULL"}
	primCombo, _ := add_drop_down(mode_box_lhs, "Block cipher: ", blockCiphers, 0)
	modes := []string{"ECB", "CBC", "PCB", "OFB", "CFB"}
	modeCombo, _ := add_drop_down(mode_box_lhs, "Cipher mode: ", modes, 0)

	primCombo.Connect("changed", func() {
		onPrimitiveChanged(primCombo, &cipher)
	})
	modeCombo.Connect("changed", func() {
		onModeChanged(modeCombo, &modeOfOp, nil)
	})

	mode_box.PackStart(mode_box_lhs, true, true, 0)
	addVLine(mode_box, 10)

	mode_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	keyBox, _ := add_entry_box(mode_box_rhs, "Key", keySession, 16)
	keyBox.Connect("changed", func() {
		onKeyChanged(keyBox, &keySession)
	})

	keyBox.Connect("focus_out_event", func() {
		onKeyLoseFocus(keyBox, nil, &valid)
	})

	ivBox, _ := add_entry_box(mode_box_rhs, "IV", ivSession, 16)

	ivBox.Connect("changed", func() {
		onIvChanged(ivBox, &ivSession)
	})

	ivBox.Connect("focus_out_event", func() {
		onIVLoseFocus(ivBox, nil, &valid)
	})

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
		encrypt(plainText, cipherText, plaintextE, ciphertextE, keySession,
			ivSession, cipher, modeOfOp)
	})
	endecrypt_box.Add(btnEncrypt)

	btnDecrypt := setup_btn("Decrypt")
	btnDecrypt.Connect("clicked", func() {
		decrypt(cipherText, plainText, plaintextE, ciphertextE, keySession,
			cipher, modeOfOp)
	})
	endecrypt_box.Add(btnDecrypt)

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

	return main_box, nil
}
