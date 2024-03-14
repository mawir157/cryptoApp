package main

import (
	"github.com/gotk3/gotk3/gtk"

	"fmt"
	"strconv"

	JMT "github.com/mawir157/jmtcrypto"
)

func humanReadbleRNG(rngMode PRNGType, seed int) string {
	str := ""
	switch rngMode {
	case Mersenne:
		str = "Mersenne twister"
	case PCG:
		str = "PCG"
	default:
		fmt.Printf("Unidentified Encoding (INPUT) %d.\n", rngMode)
		str = "ERROR"
	}

	return fmt.Sprintf("%s with seed %d", str, seed)
}

func onNext(outBox *gtk.Entry, rng *JMT.PRNG) {
	v := (*rng).Next()

	outBox.SetText(strconv.Itoa(v))
}

func onSeedChanged(seedBox *gtk.Entry, seed *int) {
	v, _ := seedBox.GetText()

	i, err := strconv.Atoi(v)
	if err != nil {

		return
	}

	*seed = i
}

func onSeedLoseFocus(seedBox *gtk.Entry, seed *int) {
	onSeedChanged(seedBox, seed)
}

func onRNGChanged(cb *gtk.ComboBoxText, rngMode *PRNGType) {
	switch enc := cb.GetActiveText(); enc {
	case "Mersenne":
		*rngMode = Mersenne
	case "PCG":
		*rngMode = PCG
	default:
		fmt.Printf("Unidentified Encoding (INPUT)%s.\n", enc)
		*rngMode = Mersenne
	}
}

func onRNGReset(rngMode PRNGType, rng *JMT.PRNG, seed int, btn *gtk.Button,
	lbl *gtk.Label) {
	switch rngMode {
	case Mersenne:
		*rng = JMT.Mersenne19937Init()
	case PCG:
		*rng = JMT.PCGInit()
	default:
		fmt.Printf("Unidentified rng mode %d.\n", rngMode)
	}

	(*rng).Seed(seed)

	btn.SetSensitive(true)
	lbl.SetLabel(humanReadbleRNG(rngMode, seed))
}

func rngTab() (*gtk.Box, error) {
	sessionSeed := 5489

	rngMode := Mersenne
	seed := sessionSeed
	var rng JMT.PRNG

	main_box := setup_box(gtk.ORIENTATION_VERTICAL)
	rngSetupBox := setup_box(gtk.ORIENTATION_HORIZONTAL)

	rngs := []string{"Mersenne", "PCG"}
	rngCombo, _ := add_drop_down(rngSetupBox, "Pseudo-RNG function: ", rngs, 0)
	rngCombo.Connect("changed", func() {
		onRNGChanged(rngCombo, &rngMode)
	})

	seedEntry, _ := add_entry_box(rngSetupBox, "Seed", strconv.Itoa(sessionSeed), 10)
	seedEntry.Connect("changed", func() {
		onSeedChanged(seedEntry, &seed)
	})
	seedEntry.Connect("focus_out_event", func() {
		onSeedLoseFocus(seedEntry, &seed)
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
		onNext(valueEntry, &rng)
	})
	nextBtn.SetSensitive(false)

	resetBtn := addButton(rngSetupBox, "Reset RNG")
	resetBtn.Connect("clicked", func() {
		onRNGReset(rngMode, &rng, seed, nextBtn, rngLabel)
	})

	main_box.PackStart(doBox, false, true, 10)

	onRNGReset(rngMode, &rng, seed, nextBtn, rngLabel)

	return main_box, nil
}
