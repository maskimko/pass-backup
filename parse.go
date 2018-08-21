package main

import (
	"PassEncBkp/Pass"
	"PassEncBkp/PasswordSafe"
	"fmt"
	"log"
	"os"

	"github.com/howeyc/gopass"
	"github.com/pborman/getopt"
)

var configuration *config

func main() {

	optEmailId := getopt.StringLong("email", 'e', "", "Your PGP identity email address")
	optPassPrefix := getopt.StringLong("prefix", 'p', "/", "Which directory in password store should be considered as entry point")
	optPasswordSafeFile := getopt.StringLong("PasswordSafe", 'P', "", "Exported CSV file with PasswordSafe data")
	optConfigurationFile := getopt.StringLong("config", 'c', "PassEncBkp.conf", "Configuration file")
	helpFlag := getopt.Bool('?', "Display help")
	getopt.Parse()
	if *helpFlag {
		getopt.Usage()
		os.Exit(0)
	}

	configuration, err := readConfiguration(*optConfigurationFile)
	if err != nil {
		log.Printf("Cannot parse configuration from file %s\nDetails: %s", *optConfigurationFile, err)
	}

	var password string
	var gpgId string
	var prefix string
	var psf string
	if configuration != nil && configuration.GpgPassword != "" {
		password = configuration.GpgPassword
	} else {
		//Obtain the passphrase
		log.Printf("Input the passphrase: ")
		passphrase, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}
		password = string(passphrase)
	}
	if configuration != nil && configuration.GpgId != "" {
		gpgId = configuration.GpgId
	}
	if *optEmailId != "" {
		gpgId = *optEmailId
	}

	if configuration != nil && configuration.Prefix != "" {
		prefix = configuration.Prefix
	}
	if *optPassPrefix != "" {
		prefix = *optPassPrefix
	}
	if configuration != nil && configuration.PasswordSafeFile != "" {
		psf = configuration.PasswordSafeFile
	}
	if *optPasswordSafeFile != "" {
		psf = *optPasswordSafeFile
	}

	var creds *Pass.GpgCredentilas = &Pass.GpgCredentilas{EmailId: gpgId, Passphrase: password}
	precs, err := Pass.GetPassRecords(prefix, creds)
	if err != nil {
		log.Println("Cannot get Pass passwords", err)
	} else {
		//log.Println("Pass records")
		for i := range precs {
			fmt.Printf("Pass record:\n\t%v\n", *precs[i])
		}
	}

	if psf != "" {
		psr, err := PasswordSafe.ReadRecords(psf, nil, nil)
		if err != nil {
			log.Println(err)
		} else {
			//log.Println("PasswordSafe records")
			for i := range psr {
				fmt.Printf("PasswordSafe record:\n\t%v\n", *psr[i])
			}
		}
	}

	log.Println("End of program")
}
