package main

import (
    "log"
    "strconv"

    "github.com/gotk3/gotk3/gtk"
)

func setup_window(title string) *gtk.Window {
    win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
    if err != nil {
        log.Fatal("Unable to create window:", err)
    }
    win.SetTitle(title)
    win.Connect("destroy", func() {
        gtk.MainQuit()
    })
    win.SetDefaultSize(800, 600)
    win.SetPosition(gtk.WIN_POS_CENTER)
    return win
}

func setup_box(orient gtk.Orientation) *gtk.Box {
    box, err := gtk.BoxNew(orient, 0)
    if err != nil {
        log.Fatal("Unable to create box:", err)
    }
    return box
}

func setup_tview() *gtk.TextView {
    tv, err := gtk.TextViewNew()
    if err != nil {
        log.Fatal("Unable to create TextView:", err)
    }
    return tv
}

func setup_btn(label string) *gtk.Button {
    btn, err := gtk.ButtonNewWithLabel(label)
    if err != nil {
        log.Fatal("Unable to create button:", err)
    }

    return btn
}

func get_buffer_from_tview(tv *gtk.TextView) *gtk.TextBuffer {
    buffer, err := tv.GetBuffer()
    if err != nil {
        log.Fatal("Unable to get buffer:", err)
    }
    return buffer
}

func get_text_from_tview(tv *gtk.TextView) string {
    buffer := get_buffer_from_tview(tv)
    start, end := buffer.GetBounds()

    text, err := buffer.GetText(start, end, true)
    if err != nil {
        log.Fatal("Unable to get text:", err)
    }
    return text
}

func set_text_in_tview(tv *gtk.TextView, text string) {
    buffer := get_buffer_from_tview(tv)
    buffer.SetText(text)
}

func add_drop_down(box *gtk.Box, label string, options []string, initial int) (ptrCombo *gtk.ComboBoxText, ptrLabel *gtk.Label) {
    subBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
    labelBox, err := gtk.LabelNew(label)
    labelBox.SetJustify(gtk.JUSTIFY_RIGHT)

    if err != nil {
        log.Fatal("Failed to make label:", err)
    }
    subBox.PackStart(labelBox, true, true, 0)

    comboBox, err := gtk.ComboBoxTextNew()
    if err != nil {
        log.Fatal("Failed to make combobox:", err)
    }

    for i, v := range options {
        comboBox.Insert(i, strconv.Itoa(i), v)
    }
    comboBox.SetActive(initial)
    subBox.PackStart(comboBox, true, true, 0)

    box.PackStart(subBox, false, true, 0)

    return comboBox, labelBox
}

func add_text_box(box *gtk.Box, intialText, label string) *gtk.TextView {
    if len(label) > 0 {
        frame, err := gtk.FrameNew(label)
        if err != nil {
            log.Fatal("Failed to make frame:", err)
        }
        box.PackStart(frame, true, true, 0)

				scrolled_window, _ := gtk.ScrolledWindowNew(nil, nil)
				frame.Add(scrolled_window)

        textView := setup_tview()
        textView.SetWrapMode(gtk.WRAP_WORD_CHAR)
				scrolled_window.Add(textView)

        set_text_in_tview(textView, intialText)
        

        return textView
    } else {
        textView := setup_tview()
        box.PackStart(textView, true, true, 0)
        set_text_in_tview(textView, intialText)

        return textView
    }
}

func add_entry_box(box *gtk.Box, label, intialText string) *gtk.Entry {
    subBox := setup_box(gtk.ORIENTATION_HORIZONTAL)
    labelBox, err := gtk.LabelNew(label)
    labelBox.SetJustify(gtk.JUSTIFY_RIGHT)

    if err != nil {
        log.Fatal("Failed to make label:", err)
    }
    subBox.PackStart(labelBox, true, true, 0)

    entryBox, err := gtk.EntryNew()
    if err != nil {
        log.Fatal("Failed to make entryBox:", err)
    }
    subBox.PackStart(entryBox, true, true, 0)
    entryBox.SetText(intialText)

    box.PackStart(subBox, false, true, 0)

    return entryBox
}
