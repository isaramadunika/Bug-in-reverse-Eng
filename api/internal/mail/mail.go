// Package mail sends transactional email. Development uses Mailpit (SMTP on :1025).
package mail

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

type Message struct {
	To      string
	Subject string
	Text    string
}

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

type SMTP struct {
	Host, User, Password, From string
	Port                       int
}

func (s *SMTP) Send(ctx context.Context, m Message) error {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	// Reject header injection.
	if strings.ContainsAny(m.Subject, "\r\n") {
		return fmt.Errorf("invalid subject")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", to.String())
	fmt.Fprintf(&b, "Subject: %s\r\n", m.Subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))

	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	var a smtp.Auth
	if s.User != "" {
		a = smtp.PlainAuth("", s.User, s.Password, s.Host)
	}
	done := make(chan error, 1)
	go func() { done <- smtp.SendMail(addr, a, from.Address, []string{to.Address}, []byte(b.String())) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(15 * time.Second):
		return fmt.Errorf("smtp timeout")
	}
}

// Recorder captures messages in memory for tests.
type Recorder struct {
	mu   sync.Mutex
	Sent []Message
}

func (r *Recorder) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sent = append(r.Sent, m)
	return nil
}

func (r *Recorder) Last() (Message, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.Sent) == 0 {
		return Message{}, false
	}
	return r.Sent[len(r.Sent)-1], true
}
