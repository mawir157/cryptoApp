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

    "github.com/gotk3/gotk3/gtk"
)

import JMT "github.com/mawir157/jmtcrypto"

type Encoding int
const (
    Ascii    Encoding = iota
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
    Mersenne    PRNGType = iota
    PCG
)

type Config struct {
    plaintextE   Encoding
    ciphertextE  Encoding
    cipher       BCipher
    modeOfOp     CipherMode
    key          string
    iv           string
    nonce        string
    rng          PRNGType
    seed         int
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

    s.PrintState()
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

    s.PrintState()
    return
}

func onKeyChanged(entry *gtk.Entry, s *Config) {
    s.key, _ = entry.GetText()
}

func onIvChanged(entry *gtk.Entry, s *Config) {
    s.iv, _ = entry.GetText()
}

func onNonceChanged(entry *gtk.Entry, s *Config) {
    s.nonce, _ = entry.GetText()
}

func onEncrypt(inBow, outBox *gtk.TextView, s *Config) {

    text := get_text_from_tview(inBow)

    byteStream := []byte{}
    switch enc := s.plaintextE; enc {
    case Ascii:
        byteStream = JMT.ParseFromAscii(text, true)
    case Base64:
        byteStream = JMT.ParseFromBase64(text, false)
    case Hex:
        byteStream = JMT.ParseFromHex(text, false)
    default:
        fmt.Printf("Unidentified Encoding%s.\n", enc)
        s.ciphertextE = Ascii
    }

    encryptedText := ""

    fmt.Println(len(byteStream))
    byteStream = doEncryption(byteStream, s)
    fmt.Println(len(byteStream))

    switch enc := s.ciphertextE; enc {
    case Ascii:
        encryptedText = JMT.ParseToAscii(byteStream, true)
    case Base64:
        encryptedText = JMT.ParseToBase64(byteStream)
    case Hex:
        encryptedText = JMT.ParseToHex(byteStream)
    default:
        fmt.Printf("Unidentified Encoding%s.\n", enc)
        s.ciphertextE = Ascii
    }

    set_text_in_tview(outBox, encryptedText)
}

func onDecrypt(inBow, outBox *gtk.TextView, s *Config) {

    text := get_text_from_tview(inBow)

    byteStream := []byte{}
    switch enc := s.ciphertextE; enc {
    case Ascii:
        byteStream = JMT.ParseFromAscii(text, true)
    case Base64:
        byteStream = JMT.ParseFromBase64(text, false)
    case Hex:
        byteStream = JMT.ParseFromHex(text, false)
    default:
        fmt.Printf("Unidentified Encoding%s.\n", enc)
        s.ciphertextE = Ascii
    }

    encryptedText := ""

    fmt.Println(len(byteStream))
    byteStream = doDecryption(byteStream, s)
    fmt.Println(len(byteStream))

    switch enc := s.plaintextE; enc {
    case Ascii:
        encryptedText = JMT.ParseToAscii(byteStream, true)
    case Base64:
        encryptedText = JMT.ParseToBase64(byteStream)
    case Hex:
        encryptedText = JMT.ParseToHex(byteStream)
    default:
        fmt.Printf("Unidentified Encoding%s.\n", enc)
        s.ciphertextE = Ascii
    }

    set_text_in_tview(outBox, encryptedText)
}

func (s *Config) PrintState() {
    fmt.Printf("PlainText Encryption mode: %s\n", PrintEncoding(s.plaintextE))
    fmt.Printf("PlainText Decryption mode: %s\n", PrintEncoding(s.ciphertextE))
    fmt.Printf("\n")
}

func main() {
    state := Config{plaintextE:Ascii, ciphertextE:Base64, cipher:AES,
                    modeOfOp:CBC, key:"0000000000000000", iv:"0000000000000000",
                    nonce:"0000000000000000", rng:Mersenne, seed:0}

    state.PrintState()
    gtk.Init(nil)

    win := setup_window("Simple Example")

    main_box := setup_box(gtk.ORIENTATION_VERTICAL)
////////////////////////////////////////////////////////////////////////////////
        text_box := setup_box(gtk.ORIENTATION_HORIZONTAL)
               text_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

                plainText := add_text_box(text_box_lhs, "Enter your plaintext here", "PlainText")

                encdoings := []string{"ascii", "base64", "hex"}
                ptEncoding, _ := add_drop_down(text_box_lhs, "Encoding: ", encdoings, 0)
                ptEncoding.Connect("changed", onPTEncodingChanged, &state)

        text_box.PackStart(text_box_lhs, true, true, 0)

            text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

                cipherText := add_text_box(text_box_rhs, "Cipher text here!", "CipherText")

                ctEncoding, _ := add_drop_down(text_box_rhs, "Encoding: ", encdoings, 1)
                ctEncoding.Connect("changed", onCTEncodingChanged, &state)

        text_box.PackStart(text_box_rhs, true, true, 0)

    main_box.PackStart(text_box, true, true, 0)
////////////////////////////////////////////////////////////////////////////////
        mode_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

            mode_box_lhs := setup_box(gtk.ORIENTATION_VERTICAL)

                blockCiphers := []string{"AES"}
                add_drop_down(mode_box_lhs, "Block cipher: ", blockCiphers, 0)
                               modes := []string{"ECB", "CBC", "PCB", "OFB", "CTR",
                                  "CFB", "PRNG stream"}
                add_drop_down(mode_box_lhs, "Cipher mode: ", modes, 0)

                prngs := []string{"Mersenne Twister", "PCG"}
                add_drop_down(mode_box_lhs, "Pseudo-RNGs: ", prngs, 0)

                add_entry_box(mode_box_lhs, "PRNG Seed", "123456")

        mode_box.PackStart(mode_box_lhs, true, true, 0)

            mode_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

                key_box := add_entry_box(mode_box_rhs, "Key", "0000000000000000")
                key_box.Connect("changed", onKeyChanged, &state)

                add_entry_box(mode_box_rhs, "IV", "0000000000000000")
                key_box.Connect("changed", onIvChanged, &state)

                add_entry_box(mode_box_rhs, "nonce", "0000000000000000")
                key_box.Connect("changed", onNonceChanged, &state)

               mode_box.PackStart(mode_box_rhs, true, true, 0)
    main_box.PackStart(mode_box, true, true, 0)
////////////////////////////////////////////////////////////////////////////////
        do_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

            io_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

                btnOpen := setup_btn("Open")
                io_box.Add(btnOpen)

                btnSave := setup_btn("Save")
                io_box.Add(btnSave)

                io_box.SetHAlign(gtk.ALIGN_CENTER)

            do_box.Add(io_box)

            endecrypt_box := setup_box(gtk.ORIENTATION_HORIZONTAL)

                btnEncrypt := setup_btn("Encrypt")
                btnEncrypt.Connect("clicked", func() {
                    onEncrypt(plainText, cipherText, &state)
                })
                endecrypt_box.Add(btnEncrypt)

                btnDecrypt := setup_btn("Decrypt")
                btnDecrypt.Connect("clicked", func() {
                    onDecrypt(cipherText, plainText, &state)
                })
                endecrypt_box.Add(btnDecrypt)

                endecrypt_box.SetHAlign(gtk.ALIGN_CENTER)

            do_box.Add(endecrypt_box)

        do_box.SetHAlign(gtk.ALIGN_CENTER)

    main_box.PackStart(do_box, false, true, 10)
    //         combo = Gtk.ComboBoxText()
    //     combo.insert(0, "0", "24-hour")
    //     combo.insert(1, "1", "AM/PM")
    //     hbox.pack_start(label, True, True, 0)
    //     hbox.pack_start(combo, False, True, 0)

    // text_box_rhs := setup_box(gtk.ORIENTATION_VERTICAL)

    win.Add(main_box)

    // Recursively show all widgets contained in this window.
    win.ShowAll()

    // Begin executing the GTK main loop.  This blocks until
    // gtk.MainQuit() is run.
    gtk.Main()
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