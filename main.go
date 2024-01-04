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
	"fmt"
	// "strconv"
	// "github.com/gotk3/gotk3/gdk"
	// "github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	// "time"
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

func (s *Config) PrintState() {
	fmt.Printf("PlainText Encryption mode: %s\n", PrintEncoding(s.plaintextE))
	fmt.Printf("PlainText Decryption mode: %s\n", PrintEncoding(s.ciphertextE))
	fmt.Printf("\n")
}

func main() {
	gtk.Init(nil)

	win := setup_window("Crypto Sandbox")
	winBox := setup_box(gtk.ORIENTATION_VERTICAL)
	nb, _ := gtk.NotebookNew()

	nbBlockCipher, state, _ := blockCipherTab()
	state.PrintState()
	nbBlockCipherTabLabel, _ := gtk.LabelNew("Block Cipher")
	nb.AppendPage(nbBlockCipher, nbBlockCipherTabLabel)

	nbMcE, _ := gtk.LabelNew("McEliese Encyrption Content")
	nbMcETabLab, _ := gtk.LabelNew("McEliese Encyrption")
	nb.AppendPage(nbMcE, nbMcETabLab)

	nbAE, _ := gtk.LabelNew("Authenticated Encryption Content")
	nbAETabLab, _ := gtk.LabelNew("Authenticated Encyrption")
	nb.AppendPage(nbAE, nbAETabLab)

	nbStreamCipher, _ := gtk.LabelNew("Stream Cipher Content")
	nbStreamCipherTabLab, _ := gtk.LabelNew("Stream Cipher")
	nb.AppendPage(nbStreamCipher, nbStreamCipherTabLab)

	nbRNG, _, _ := rngTab()
	nbRNGTabLab, _ := gtk.LabelNew("RNG")
	nb.AppendPage(nbRNG, nbRNGTabLab)

	nbHMAC, _, _ := hmacTab()
	nbHMACTabLab, _ := gtk.LabelNew("HMAC")
	nb.AppendPage(nbHMAC, nbHMACTabLab)

	nbSHA, _, _ := hashTab()
	nbSHATabLab, _ := gtk.LabelNew("Hash")
	nb.AppendPage(nbSHA, nbSHATabLab)

	winBox.PackStart(nb, true, true, 10)

	close_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
	btnClose := setup_btn("Close")
	btnClose.Connect("clicked", func() {
		win.Close()
	})
	close_box.Add(btnClose)
	close_box.SetHAlign(gtk.ALIGN_CENTER)

	winBox.PackStart(close_box, false, true, 0)

	win.Add(winBox)

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
