package main

import (
	"errors"
	"testing"
)

func TestRFC9530IndependentVectors(t *testing.T) {
	const expected = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
	if digestField(appendixPayload, "sha-256") != expected {
		t.Fatal("RFC9530 Appendix D mismatch")
	}
	if err := verifyFields(appendixPayload, []string{expected, digestField(appendixPayload, "sha-512")}); err != nil {
		t.Fatal(err)
	}
	if err := verifyFields([]byte("modified"), []string{expected}); !errors.Is(err, digestMismatch) {
		t.Fatal("corruption accepted", err)
	}
}
