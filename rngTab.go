package main

import (
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"fmt"
	"strconv"

	JMT "github.com/mawir157/jmtcrypto"
)

type RNGTabConfig struct {
	rngMode PRNGType
	seed    int
	rng     JMT.PRNG
	label   *gtk.Label
	widgets map[string](HackWidget)
}

func (s *RNGTabConfig) print() string {
	str := ""
	switch enc := s.rngMode; enc {
	case Mersenne:
		str = "Mersenne twister"
	case PCG:
		str = "PCG"
	default:
		fmt.Printf("Unidentified Encoding (INPUT) %d.\n", enc)
		str = "ERROR"
	}

	return fmt.Sprintf("%s with seed %d", str, s.seed)
}

func (s *RNGTabConfig) addWidget(name string, w HackWidget) {
	s.widgets[name] = w
}

func onNext(outBox *gtk.Entry, s *RNGTabConfig) {
	v := s.rng.Next()

	outBox.SetText(strconv.Itoa(v))
}

func onSeedChanged(seedBox *gtk.Entry, s *RNGTabConfig) {
	v, _ := seedBox.GetText()

	i, err := strconv.Atoi(v)
	if err != nil {

		return
	}

	s.seed = i
}

func onSeedLoseFocus(seedBox *gtk.Entry, event *gdk.Event, s *RNGTabConfig) {
	onSeedChanged(seedBox, s)
}

func onRNGChanged(cb *gtk.ComboBoxText, s *RNGTabConfig) {
	switch enc := cb.GetActiveText(); enc {
	case "Mersenne":
		s.rngMode = Mersenne
	case "PCG":
		s.rngMode = PCG
	default:
		fmt.Printf("Unidentified Encoding (INPUT)%s.\n", enc)
		s.rngMode = Mersenne
	}
}

func onRNGReset(s *RNGTabConfig) {
	switch s.rngMode {
	case Mersenne:
		s.rng = JMT.Mersenne19937Init()
	case PCG:
		s.rng = JMT.PCGInit()
	default:
		fmt.Printf("Unidentified rng mode %d.\n", s.rngMode)
	}

	s.rng.Seed(s.seed)

	s.widgets["nextBtn"].SetSensitive(true)
	s.label.SetLabel(s.print())
}

func rngTab() (*gtk.Box, *RNGTabConfig, error) {
	widgets := make(map[string](HackWidget))
	sessionSeed := 5489

	state := RNGTabConfig{rngMode: Mersenne, seed: sessionSeed, widgets: widgets}

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	rngSetupBox := setup_box(gtk.ORIENTATION_HORIZONTAL)

	rngs := []string{"Mersenne", "PCG"}
	rngCombo, _ := add_drop_down(rngSetupBox, "Pseudo-RNG function: ", rngs, 0)
	rngCombo.Connect("changed", func() {
		onRNGChanged(rngCombo, &state)
	})

	seedEntry, _ := add_entry_box(rngSetupBox, "Seed", strconv.Itoa(sessionSeed), 10)
	seedEntry.Connect("changed", func() {
		onSeedChanged(seedEntry, &state)
	})
	seedEntry.Connect("focus_out_event", func() {
		onSeedLoseFocus(seedEntry, nil, &state)
	})

	resetBtn := addButton(rngSetupBox, "Reset RNG")
	resetBtn.Connect("clicked", func() {
		onRNGReset(&state)
	})

	main_box.PackStart(rngSetupBox, false, true, 10)

	rngLabel, _ := gtk.LabelNew("Pseudo random number not set")
	main_box.PackStart(rngLabel, false, true, 10)

	doBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
	nextBtn := addButton(doBox, "Next")

	valueEntry, _ := add_entry_box(doBox, "Random number", "-", 100)
	valueEntry.SetCanFocus(false)
	valueEntry.SetEditable(false)

	nextBtn.Connect("clicked", func() {
		onNext(valueEntry, &state)
	})
	nextBtn.SetSensitive(false)

	main_box.PackStart(doBox, false, true, 10)

	state.addWidget("rngCombo", rngCombo)
	state.addWidget("seedEntry", seedEntry)
	state.addWidget("resetBtn", resetBtn)
	state.addWidget("nextBtn", nextBtn)
	state.addWidget("valueEntry", valueEntry)
	state.label = rngLabel

	onRNGReset(&state)

	/*
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

			inputEncCombo.Connect("changed", onInputEncodingChanged, &state)
			outputEncCombo.Connect("changed", onOutputEncodingChanged, &state)

			btnHash := setup_btn("Hash")
			IOBox.Add(btnHash)

			IOBox.SetHAlign(gtk.ALIGN_CENTER)

		main_box.PackStart(IOBox, false, true, 10)

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

	*/
	return main_box, &state, nil
}
