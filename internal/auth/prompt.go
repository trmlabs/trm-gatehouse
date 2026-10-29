package auth

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptPassword reads a password from the terminal with echo suppressed.
func PromptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return password, nil
}

// PromptNewPassword prompts for a password twice and checks that they match.
func PromptNewPassword(prompt, confirm string) ([]byte, error) {
	pw1, err := PromptPassword(prompt)
	if err != nil {
		return nil, err
	}
	pw2, err := PromptPassword(confirm)
	if err != nil {
		return nil, err
	}

	if len(pw1) != len(pw2) || string(pw1) != string(pw2) {
		return nil, errors.New("passwords do not match")
	}

	return pw1, nil
}

// PromptEmail prompts for an email address from the terminal (visible input).
func PromptEmail(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading email: %w", err)
	}
	email := strings.TrimSpace(line)
	if err := ValidateEmail(email); err != nil {
		return "", err
	}
	return email, nil
}
