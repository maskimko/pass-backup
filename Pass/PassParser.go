package Pass

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

type PassRecord struct {
	Password    string
	Login       string
	Url         string
	Email       string
	Description string
	Version     int8
	Notes       string
	Path        []string
}

func New(password *string, login *string, url *string, email *string, desc *string, path *[]string, ver int8, notes *string) *PassRecord {
	return &PassRecord{
		Password:    *password,
		Login:       *login,
		Url:         *url,
		Email:       *email,
		Description: *desc,
		Version:     ver,
		Notes:       *notes,
		Path:        *path}
}

func Parse(s *string, passLocation *[]string) (*PassRecord, error) {
	var password, login, email, url, description string
	var version int8
	// NOTE: implement templating somewhen
	var pr PassRecord
	if passLocation == nil {
		passLocation = &[]string{"unknown"}
	}
	counter := 0
	var notes []string
	scanner := bufio.NewScanner(strings.NewReader(*s))
	for scanner.Scan() {
		counter++
		text := scanner.Text()
		if counter == 1 {
			password = text
			continue
		}
		tokens := strings.SplitN(text, ":", 2)
		if len(tokens) == 1 {
			notes = append(notes, tokens[0])
		}
		switch tokens[0] {
		case "login":
			login = strings.TrimSpace(tokens[1])
		case "url":
			url = strings.TrimSpace(tokens[1])
		case "e-mail":
			email = strings.TrimSpace(tokens[1])
		case "version":
			v, err := strconv.ParseInt(strings.TrimSpace(tokens[1]), 10, 8)
			if err != nil {
				fmt.Printf("Cannot parse version of password from string %s", tokens[1])
				return nil, err
			}
			version = int8(v)
		case "description":
			description = strings.TrimSpace(tokens[1])
		default:
			notes = append(notes, text)
		}
	}
	pr = PassRecord{Password: password,
		Login:       login,
		Url:         url,
		Email:       email,
		Description: description,
		Version:     version,
		Notes:       strings.Join(notes, "\n"),
		Path:        *passLocation}
	return &pr, nil
}
