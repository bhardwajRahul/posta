// SPDX-FileCopyrightText: 2026 Jonas Kaninda
// SPDX-License-Identifier: AGPL-3.0-or-later

package email

import (
	"errors"
	"fmt"
	"net/smtp"
	"net/textproto"
	"testing"
)

func TestSmtpReply(t *testing.T) {
	// A *textproto.Error wrapped the way the net/smtp client surfaces a 550.
	rcptErr := fmt.Errorf("SMTP RCPT TO failed: %w", &textproto.Error{
		Code: 550,
		Msg:  "5.1.1 <dev-6@jkaninda.dev>: Recipient address rejected: User unknown",
	})
	code, msg := smtpReply(rcptErr)
	if code != 550 {
		t.Fatalf("smtpReply code = %d, want 550", code)
	}
	if msg == "" {
		t.Fatalf("smtpReply msg is empty, want server text")
	}

	// A plain connection error carries no SMTP reply code.
	if code, _ := smtpReply(errors.New("dial tcp: connection refused")); code != 0 {
		t.Fatalf("smtpReply code = %d for non-SMTP error, want 0", code)
	}
}

func TestSendErrorPermanent(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{550, true},
		{551, true},
		{554, true},
		{450, false}, // transient
		{421, false}, // transient
		{0, false},   // connection-level
		{250, false},
	}
	for _, c := range cases {
		se := &SendError{Code: c.code, Err: errors.New("x")}
		if got := se.Permanent(); got != c.want {
			t.Errorf("SendError{Code:%d}.Permanent() = %v, want %v", c.code, got, c.want)
		}
	}
}

func TestWrapSendError(t *testing.T) {
	orig := fmt.Errorf("SMTP RCPT TO failed: %w", &textproto.Error{Code: 550, Msg: "5.1.1 rejected"})
	err := wrapSendError("RCPT TO", "user@example.com", orig)

	var se *SendError
	if !errors.As(err, &se) {
		t.Fatalf("wrapSendError result is not a *SendError")
	}
	if se.Stage != "RCPT TO" || se.Recipient != "user@example.com" || se.Code != 550 {
		t.Fatalf("unexpected SendError: %+v", se)
	}
	if !se.Permanent() {
		t.Fatalf("550 should be permanent")
	}
	// Error string must be preserved unchanged for storage/logging.
	if se.Error() != orig.Error() {
		t.Fatalf("Error() = %q, want %q", se.Error(), orig.Error())
	}
}

func TestAuthPrefersPlainWhenOffered(t *testing.T) {
	a := newAuth("mail.example.com", "user", "secret")
	mech, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true, Auth: []string{"LOGIN", "PLAIN"}})
	if err != nil || mech != "PLAIN" {
		t.Fatalf("mech=%q err=%v, want PLAIN", mech, err)
	}
}

func TestAuthFallsBackToPlainWhenNothingAdvertised(t *testing.T) {
	a := newAuth("mail.example.com", "user", "secret")
	mech, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true})
	if err != nil || mech != "PLAIN" {
		t.Fatalf("mech=%q err=%v, want PLAIN", mech, err)
	}
}

func TestAuthUsesLoginWhenPlainNotOffered(t *testing.T) {
	a := newAuth("smtp.office365.com", "user", "secret")
	mech, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.office365.com", TLS: true, Auth: []string{"LOGIN", "XOAUTH2"}})
	if err != nil || mech != "LOGIN" {
		t.Fatalf("mech=%q err=%v, want LOGIN", mech, err)
	}
	if got, _ := a.Next([]byte("Username:"), true); string(got) != "user" {
		t.Fatalf("username challenge answered with %q", got)
	}
	if got, _ := a.Next([]byte("Password:"), true); string(got) != "secret" {
		t.Fatalf("password challenge answered with %q", got)
	}
	if _, err := a.Next([]byte("Nonce:"), true); err == nil {
		t.Fatal("unexpected challenge must fail")
	}
}

func TestAuthLoginRefusesUnencryptedConnection(t *testing.T) {
	a := newAuth("smtp.office365.com", "user", "secret")
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.office365.com", Auth: []string{"LOGIN"}}); err == nil {
		t.Fatal("LOGIN over plaintext must be refused")
	}
}
