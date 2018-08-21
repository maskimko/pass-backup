package main

import (
	"io/ioutil"
	"log"
	"strings"
)

type config struct {
	GpgId            string
	GpgPassword      string
	PasswordSafeFile string
	Prefix           string
}

var configFile string

func readConfiguration(sourceFile string) (*config, error) {
	dat, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(dat), "\n")
	var email string = ""
	var gpgPass string = ""
	var psf string = ""
	var prefix string = ""
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if len(trimmed) == 0 {
			//Ignore empty lines
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			//Ignore comments
			continue
		}
		keyval := strings.SplitN(trimmed, "=", 2)
		if len(keyval) != 2 {
			log.Printf("Cannot parse configuration line %s\n", trimmed)
		} else {
			switch strings.TrimSpace(keyval[0]) {
			case "email":
				email = strings.TrimSpace(keyval[1])
			case "gpg_key_id":
				email = strings.TrimSpace(keyval[1])
			case "gpg_key_password":
				gpgPass = strings.TrimSpace(keyval[1])
			case "password_safe_file":
				psf = strings.TrimSpace(keyval[1])
			case "prefix":
				prefix = strings.TrimSpace(keyval[1])
			default:
				log.Printf("Don't know how to handle \"%s\" configuration statement\n", trimmed)
			}
		}
	}
	return &config{GpgId: email, GpgPassword: gpgPass, PasswordSafeFile: psf, Prefix: prefix}, nil
}
