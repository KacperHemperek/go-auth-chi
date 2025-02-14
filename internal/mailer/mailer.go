package mailer

import "fmt"

type Mailer interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
}

type AppMailer struct {
	from string
}

func (m *AppMailer) SendVerificationEmail(to, token string) error {
	// Send an mail to the user with the verification token
	fmt.Printf("Sending mail to %s from %s with token: %s\n", m.from, to, token)
	return nil
}

func (m *AppMailer) SendPasswordResetEmail(to, token string) error {
	// Send an mail to the user with the password reset token
	fmt.Printf("Sending mail to %s from %s with token: %s\n", m.from, to, token)
	return nil
}

func New() *AppMailer {
	return &AppMailer{
		from: "autosend@go-auth.com",
	}
}
