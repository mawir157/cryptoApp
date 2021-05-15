/*
 * Copyright (c) 2013-2014 Conformal Systems <info@conformal.com>
 *
 * This file originated from: http://opensource.conformal.com/
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"encoding/hex"
	"encoding/base64"
	"fmt"
	"strconv"
	"github.com/gotk3/gotk3/gdk"
	// "github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
  "math/rand"
  "time"
)

type Encoding int
const (
	Ascii Encoding = iota
	Base64
	Hex
)

func PrintEncoding(i Encoding) string {
	switch i {
	case Ascii:
	return "Ascii"
	case Base64:
	return "Base64"
	case Hex:
	return "Hex"
	default:
	return "??!"
	}
}

type BCipher int
const (
	AES    BCipher = iota
	Camellia
	NULL
)

type CipherMode int
const (
	ECB    CipherMode = iota
	CBC
	PCB
	OFB
	CTR
	CFB
	PRNG
)

type PRNGType int
const (
	Mersenne   PRNGType = iota
	PCG
)

type HackWidget interface {
	SetSensitive(bool)
}

type Config struct {
	plaintextE  Encoding
	ciphertextE	Encoding
	cipher      BCipher
	modeOfOp    CipherMode
	key         string
	iv          string
	nonce       string
	rng         PRNGType
	seed        int
	valid       bool
	widgets     map[string](HackWidget)
}

func (s *Config) addWidget(name string, w HackWidget) {
	s.widgets[name] = w
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int, r *rand.Rand) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rune(letters[r.Intn(len(letters))])
	}
	return string(b)
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

func onRNGChanged(cb *gtk.ComboBoxText, s *Config) {
	switch enc := cb.GetActiveText(); enc {
	case "Mersenne Twister":
		s.rng = Mersenne
	case "PCG":
		s.rng = PCG
	default:
		fmt.Printf("Unidentified Encoding%s.\n", enc)
		s.rng = Mersenne
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

	if nonce {
		s.widgets["nonceBox"].SetSensitive(true)
		s.widgets["nonceLabel"].SetSensitive(true)
	}

	if prim {
		s.widgets["primCombo"].SetSensitive(true)
		s.widgets["primLabel"].SetSensitive(true)
	}

	if rng {
		s.widgets["rngCombo"].SetSensitive(true)
		s.widgets["rngLabel"].SetSensitive(true)
	}

	return
}

// func SetActive(s *Config) {
//	 // set everything to false
//	 for k, _ := range s.widgets {
//		 s.widgets[k].SetSensitive(false)
//	 }
//	 // put modeCombo back on
//	 s.widgets["modeCombo"].SetSensitive(false)

//	 // step 1 grab the 
//	 mode := s.widgets["modeCombo"].GetActiveText()
// }

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
	}	else {
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

func onNonceChanged(entry *gtk.Entry, s *Config) {
	s.nonce, _ = entry.GetText()
}

func onNonceLoseFocus(entry *gtk.Entry, event *gdk.Event, s *Config) {
	name := "nonce"
	required := 8
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

func onSeedChanged(entry *gtk.Entry, s *Config) {
	seedString, _ := entry.GetText()
	seed, err := strconv.Atoi(seedString)

	if err != nil {
		s.valid = false
		s.widgets["btnEncrypt"].SetSensitive(false)

		title := "Seed error"
		message := "Seed must be an integer."

		dialog := makeOKDialog(title, message)
		dialog.Run()
		dialog.Destroy()

		return
	}

	s.seed = seed
	s.valid = true
	s.widgets["btnEncrypt"].SetSensitive(true)

	return
}



func validateButton(btn *gtk.Button, s *Config) {
	btn.SetSensitive(s.valid)

	return 
}

func (s *Config) PrintState() {
	fmt.Printf("PlainText Encryption mode: %s\n", PrintEncoding(s.plaintextE))
	fmt.Printf("PlainText Decryption mode: %s\n", PrintEncoding(s.ciphertextE))
	fmt.Printf("\n")
}

func main() {
	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way - in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	keySession   := randString(16, r1)
	ivSession    := randString(16, r1)
	nonceSession := randString(8, r1)
	seedSession  := r1.Intn(50000000) + r1.Intn(50000000)

	widgets := make(map[string](HackWidget))
	state := Config{plaintextE:Ascii, ciphertextE:Base64, cipher:AES,
                  modeOfOp:ECB, key:keySession, iv:ivSession,
                  nonce:nonceSession, rng:Mersenne, seed:seedSession,
                  valid:true, widgets:widgets}

	state.PrintState()
	gtk.Init(nil)

	win := setup_window("Crypto Sandbox")
	nb, _ := gtk.NotebookNew()

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
////////////////////////////////////////////////////////////////////////////////
		text_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
				 text_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

				plainText := add_text_box(text_box_lhs, textMessage, "PlainText")

				encdoings := []string{"ascii", "base64", "hex"}
				ptEncoding, _ := add_drop_down(text_box_lhs, "Encoding: ", encdoings, 0)
				ptEncoding.Connect("changed", onPTEncodingChanged, &state)

		text_box.PackStart(text_box_lhs, true, true, 0)
		addVLine(text_box, 10)

			text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

				cipherText := add_text_box(text_box_rhs, "Cipher text here!", "CipherText")

				ctEncoding, _ := add_drop_down(text_box_rhs, "Encoding: ", encdoings[1:], 0)
				ctEncoding.Connect("changed", onCTEncodingChanged, &state)

		text_box.PackStart(text_box_rhs, true, true, 0)

	main_box.PackStart(text_box, true, true, 0)
	addHLine(main_box, 10)
////////////////////////////////////////////////////////////////////////////////
		mode_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

			mode_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

				blockCiphers := []string{"AES", "Camellia", "NULL"}
				primCombo, primLabel := add_drop_down(mode_box_lhs, "Block cipher: ", blockCiphers, 0)
								 modes := []string{"ECB", "CBC", "PCB", "OFB", "CTR",
									"CFB", "PRNG stream"}
				modeCombo, _ := add_drop_down(mode_box_lhs, "Cipher mode: ", modes, 0)

				primCombo.Connect("changed", onPrimitiveChanged, &state)
				modeCombo.Connect("changed", onModeChanged, &state)
				state.addWidget("modeCombo", modeCombo)
				state.addWidget("primCombo", primCombo)
				state.addWidget("primLabel", primLabel)

				prngs := []string{"Mersenne Twister", "PCG"}
				rngCombo, rngLabel := add_drop_down(mode_box_lhs, "Pseudo-RNGs: ", prngs, 0)
				rngCombo.Connect("changed", onRNGChanged, &state)
				state.addWidget("rngCombo", rngCombo)
				state.addWidget("rngLabel", rngLabel)

				seedBox, seedLabel := add_entry_box(mode_box_lhs, "PRNG Seed", strconv.Itoa(state.seed), 8)
				seedBox.Connect("changed", onSeedChanged, &state)
				state.addWidget("seedBox", seedBox)
				state.addWidget("seedLabel", seedLabel)

		mode_box.PackStart(mode_box_lhs, true, true, 0)
		addVLine(mode_box, 10)

			mode_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

				keyBox, keyLabel := add_entry_box(mode_box_rhs, "Key", state.key, 16)
				keyBox.Connect("changed", onKeyChanged, &state)
				keyBox.Connect("focus_out_event", onKeyLoseFocus, &state)
				state.addWidget("keyBox", keyBox)
				state.addWidget("keyLabel", keyLabel)

				ivBox, ivLabel := add_entry_box(mode_box_rhs, "IV", state.iv, 16)
				ivBox.Connect("changed", onIvChanged, &state)
				ivBox.Connect("focus_out_event", onIVLoseFocus, &state)
				state.addWidget("ivBox", ivBox)
				state.addWidget("ivLabel", ivLabel)

				nonceBox, nonceLabel := add_entry_box(mode_box_rhs, "nonce", state.nonce, 8)
				nonceBox.Connect("changed", onNonceChanged, &state)
				nonceBox.Connect("focus_out_event", onNonceLoseFocus, &state)
				state.addWidget("nonceBox", nonceBox)
				state.addWidget("nonceLabel", nonceLabel)

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
				btnClose.Connect("clicked", func() {
					win.Close()
				})
				close_box.Add(btnClose)

				close_box.SetHAlign(gtk.ALIGN_CENTER)

			do_box.Add(close_box)
			addHLine(do_box, 10)

		do_box.SetHAlign(gtk.ALIGN_CENTER)

	main_box.PackStart(do_box, false, true, 10)
	addHLine(main_box, 10)

	nbTabLabel, _ := gtk.LabelNew("Block Cipher")
	nb.AppendPage(main_box, nbTabLabel)

	nbMcE, _ := gtk.LabelNew("McEliese Encyrption Content")
	nbMcETabLab, _ := gtk.LabelNew("McEliese Encyrption")	
	nb.AppendPage(nbMcE, nbMcETabLab)

	nbAE, _ := gtk.LabelNew("Authenticated Encryption Content")
	nbAETabLab, _ := gtk.LabelNew("Authenticated Encyrption")	
	nb.AppendPage(nbAE, nbAETabLab)

	nbStreamCipher, _ := gtk.LabelNew("Stream Cipher Content")
	nbStreamCipherTabLab, _ := gtk.LabelNew("Stream Cipher")	
	nb.AppendPage(nbStreamCipher, nbStreamCipherTabLab)

	nbRNG, _ := gtk.LabelNew("RNG Content")
	nbRNGTabLab, _ := gtk.LabelNew("RNG")	
	nb.AppendPage(nbRNG, nbRNGTabLab)

	nbHMAC, _ := gtk.LabelNew("HMAC Content")
	nbHMACTabLab, _ := gtk.LabelNew("HMAC")	
	nb.AppendPage(nbHMAC, nbHMACTabLab)

	nbSHA, _ := gtk.LabelNew("SHA Content")
	nbSHATabLab, _ := gtk.LabelNew("SHA")	
	nb.AppendPage(nbSHA, nbSHATabLab)

	win.Add(nb)

	// win.Add(main_box)

	// Recursively show all widgets contained in this window.
	win.ShowAll()

	// Begin executing the GTK main loop.	This blocks until
	// gtk.MainQuit() is run.
	gtk.Main()

	return
}

/*
    -------------------------------------------------------------
    |                       TEXT_BOX                            |
    | --------------------------------------------------------- |
    | |                         |                             | |
    | |     TEXT_BOX_LHS        |        TEXT_BOX_RHS         | |
    | | ---------------------   |   ---------------------     | |
    | | |                   |   |   |                   |     | |
    | | |     TEX_LHS       |   |   |     TEX_RHS       |     | |
    | | |                   |   |   |                   |     | |
    | | |                   |   |   |                   |     | |
    | | ---------------------   |   ---------------------     | |
    | |                         |                             | |
    | | | HEX/BASE64/ASCII |V|  |   | HEX/BASE64/ASCII |V|    | |
    | |                         |                             | |
    | --------------------------------------------------------| |
    -------------------------------------------------------------
    |                         MODE_BOX                          |
    | --------------------------------------------------------- |
    | |       MODE_BOX_LHS       |       MODE_BOX_RHS         | |
    | | |PRIM_DROP|  |ENC_MODE|  |  | KEY_TEXT | | KEY_OK |   | |
    | | |INFORMATIVE_ERRORS|X|   |                            | |
    | --------------------------------------------------------- |
    ------------------------------------------------------------|
    |                        DO_BOX                             |
    |                  | ENCRPYT| |DECTRPY|                     |
    -------------------------------------------------------------
*/
