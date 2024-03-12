package main

import (
	"errors"
	"fmt"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"math/rand"
	"time"
)

func aeEncodingChanged(cb *gtk.ComboBoxText, encoding *Encoding) error {
	switch enc := cb.GetActiveText(); enc {
	case "ascii":
		*encoding = Ascii
	case "base64":
		*encoding = Base64
	case "hex":
		*encoding = Hex
	default:
		return errors.New("unidentified encoding (INPUT)")
	}

	return nil
}

func aePrimitiveChanged(cb *gtk.ComboBoxText, s *BCipher) error {
	switch enc := cb.GetActiveText(); enc {
	case "AES":
		*s = AES
	case "Camellia":
		*s = Camellia
	case "NULL":
		*s = NULL
	default:
		return errors.New("unidentified primitive")
	}

	return nil
}

func aeModeChanged(cb *gtk.ComboBoxText, s *CipherMode) error {
	switch enc := cb.GetActiveText(); enc {
	case "ECB":
		*s = ECB
	case "CBC":
		*s = CBC
	case "PCB":
		*s = PCB
	case "OFB":
		*s = OFB
	case "CTR":
		*s = CTR
	case "CFB":
		*s = CFB
	case "PRNG stream":
		*s = PRNG
	default:
		return errors.New("unidentified cipher mode")
	}

	return nil
}

func aeKeyChanged(entry *gtk.Entry, s *string) {
	*s, _ = entry.GetText()
}

func aeKeyLoseFocus(entry *gtk.Entry, event *gdk.Event, s *bool) {
	name := "Key"
	required := 16

	key, _ := entry.GetText()
	if len(key) != 16 {
		*s = false
		title := fmt.Sprintf("%s length warning", name)
		message := fmt.Sprintf("Warning!\n %s must be exactly\n%d bytes.",
			name, required)

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()
		return
	} else {
		*s = true
	}
}

func authEncryptTab() (*gtk.Box, error) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	keySession := randString(16, r1)
	// keySession2 := randString(16, r1)
	ivSession := randString(16, r1)

	plainTextE := Ascii
	ciphertextE := Base64
	cipher := AES
	modeOfOp := ECB

	valid := true

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	////////////////////////////////////////////////////////////////////////////
	text_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
	text_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	plainText := add_text_box(text_box_lhs, TextMessage, "PlainText")

	encodings := []string{"ascii", "base64", "hex"}
	ptEncoding, _ := add_drop_down(text_box_lhs, "Encoding: ", encodings, 0)
	ptEncoding.Connect("changed", func() {
		aeEncodingChanged(ptEncoding, &plainTextE)
	})

	text_box.PackStart(text_box_lhs, true, true, 0)
	addVLine(text_box, 10)

	text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	cipherText := add_text_box(text_box_rhs, "Cipher text here!", "CipherText")
	_, _ = add_mac_box(text_box_rhs, "MAC")

	ctEncoding, _ := add_drop_down(text_box_rhs, "Encoding: ", encodings[1:], 0)
	ctEncoding.Connect("changed", func() {
		aeEncodingChanged(ctEncoding, &ciphertextE)
	})

	text_box.PackStart(text_box_rhs, true, true, 0)

	main_box.PackStart(text_box, true, true, 0)
	addHLine(main_box, 10)
	////////////////////////////////////////////////////////////////////////////
	mode_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

	mode_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

	blockCiphers := []string{"AES", "Camellia", "NULL"}
	primCombo, _ := add_drop_down(mode_box_lhs, "Block cipher: ", blockCiphers, 0)
	modes := []string{"ECB", "CBC", "PCB", "OFB", "CFB"}
	modeCombo, _ := add_drop_down(mode_box_lhs, "Cipher mode: ", modes, 0)

	primCombo.Connect("changed", func() {
		aePrimitiveChanged(primCombo, &cipher)
	})
	modeCombo.Connect("changed", func() {
		aeModeChanged(modeCombo, &modeOfOp)
	})

	mode_box.PackStart(mode_box_lhs, true, true, 0)
	addVLine(mode_box, 10)

	mode_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

	keyBox, _ := add_entry_box(mode_box_rhs, "Key", keySession, 16)
	keyBox.Connect("changed", func() {
		aeKeyChanged(keyBox, &keySession)
	})

	keyBox.Connect("focus_out_event", func() {
		aeKeyLoseFocus(keyBox, nil, &valid)
	})

	ivBox, _ := add_entry_box(mode_box_rhs, "IV", ivSession, 16)

	ivBox.Connect("changed", func() {
		aeKeyChanged(ivBox, &ivSession)
	})

	ivBox.Connect("focus_out_event", func() {
		aeKeyLoseFocus(ivBox, nil, &valid)
	})

	mode_box.PackStart(mode_box_rhs, true, true, 0)
	main_box.PackStart(mode_box, true, true, 0)
	addHLine(main_box, 10)
	////////////////////////////////////////////////////////////////////////////
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
		newEncrypt(plainText, cipherText, plainTextE, ciphertextE, keySession,
			ivSession, cipher, modeOfOp)
	})
	endecrypt_box.Add(btnEncrypt)

	btnDecrypt := setup_btn("Decrypt")
	btnDecrypt.Connect("clicked", func() {
		newDecrypt(cipherText, plainText, plainTextE, ciphertextE, keySession,
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
