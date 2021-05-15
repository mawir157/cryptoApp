package main

import (
	"math/rand"
)

// This file contains data/ functions that will be uses across all tabs
// it is a mess at present but will become better when I have a clearer idea of
// wtf I am doing!

type Encoding int
const (
	Ascii Encoding = iota
	Base64
	Hex
)

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

type HashMode int
const (
	SHA256	HashMode = iota
	SHA512
)

type HackWidget interface {
	SetSensitive(bool)
}

var	TextMessage =
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way - in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

var LoremIpsum = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Duis at consectetur lorem donec massa sapien faucibus. Eu facilisis sed odio morbi quis commodo odio aenean sed. Lectus sit amet est placerat in egestas erat imperdiet sed. Quis risus sed vulputate odio ut enim blandit volutpat. Donec enim diam vulputate ut pharetra sit amet. Pharetra massa massa ultricies mi. At augue eget arcu dictum. Rhoncus urna neque viverra justo nec ultrices dui. Convallis tellus id interdum velit laoreet id donec ultrices tincidunt. Leo a diam sollicitudin tempor id eu. Sollicitudin ac orci phasellus egestas tellus rutrum tellus pellentesque eu. Diam in arcu cursus euismod quis. Et pharetra pharetra massa massa ultricies mi. Cras sed felis eget velit aliquet sagittis. Auctor urna nunc id cursus metus aliquam eleifend. Cras ornare arcu dui vivamus arcu. Vitae tortor condimentum lacinia quis vel eros. Pellentesque adipiscing commodo elit at.

Elit ut aliquam purus sit amet luctus venenatis lectus magna. Morbi quis commodo odio aenean sed adipiscing diam donec. Id leo in vitae turpis massa sed elementum tempus egestas. Dis parturient montes nascetur ridiculus mus mauris vitae. Mauris sit amet massa vitae tortor condimentum lacinia quis. Nisl purus in mollis nunc sed. Quisque sagittis purus sit amet volutpat consequat mauris nunc congue. Sit amet facilisis magna etiam. Consequat semper viverra nam libero justo laoreet. Lobortis elementum nibh tellus molestie nunc non. Et malesuada fames ac turpis egestas sed tempus. Adipiscing bibendum est ultricies integer quis auctor. Odio aenean sed adipiscing diam donec adipiscing tristique risus nec. Integer eget aliquet nibh praesent tristique magna sit amet. Aenean euismod elementum nisi quis eleifend quam adipiscing vitae. Sit amet mattis vulputate enim nulla aliquet porttitor lacus.`

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int, r *rand.Rand) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rune(letters[r.Intn(len(letters))])
	}
	return string(b)
}