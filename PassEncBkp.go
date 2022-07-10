package main

import (
	"fmt"
	"log"
	"os"

	"github.com/maskimko/pass-backup/Pass"
	"github.com/maskimko/pass-backup/PasswordSafe"

	"github.com/howeyc/gopass"
	"github.com/pborman/getopt"
)

var configuration *config

func main() {

	optEmailId := getopt.StringLong("email", 'e', "", "Your PGP identity email address for Pass decryption")
	optPassPrefix := getopt.StringLong("prefix", 'p', "/", "Which directory in password store should be considered as entry point")
	optPasswordSafeFile := getopt.StringLong("PasswordSafe", 'P', "", "Exported CSV file with PasswordSafe data")
	optConfigurationFile := getopt.StringLong("config", 'c', "PassEncBkp.conf", "Configuration file")
	optEncGpgId := getopt.StringLong("gpgId", 'g', "", "PGP identity email address to encrypt output file")
	optBase64 := getopt.Bool('b', "Use base64 when encrypting")
	optOutputFile := getopt.StringLong("output", 'o', "", "Output file to save merged passwords")
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
	var output string
	var encGpgId string
	var base64 bool
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
	if configuration != nil {
		output = configuration.Output
	}
	if *optOutputFile != "" {
		output = *optOutputFile
	}
	if configuration != nil && configuration.EncGpgId != "" {
		encGpgId = configuration.EncGpgId
	}
	if *optEncGpgId != "" {
		encGpgId = *optEncGpgId
	}
	if configuration != nil {
		base64 = configuration.Base64
	}
	base64 = base64 || *optBase64

	var d *dumper = getDumper(&output, 512)

	var creds *Pass.GpgCredentilas = &Pass.GpgCredentilas{EmailId: gpgId, Passphrase: password}
	precs, err := Pass.GetPassRecords(prefix, creds)
	if err != nil {
		log.Println("Cannot get Pass passwords", err)
	} else {
		//log.Println("Pass records")
		for i := range precs {
			var formattedString string = fmt.Sprintf("Pass record:\n\t%v\n", *precs[i])
			d.WriteString(&formattedString)
		}
	}

	if psf != "" {
		psr, err := PasswordSafe.ReadRecords(psf, nil, nil)
		if err != nil {
			log.Println(err)
		} else {
			//log.Println("PasswordSafe records")
			for i := range psr {
				var formattedString string = fmt.Sprintf("PasswordSafe record:\n\t%v\n", *psr[i])
				d.WriteString(&formattedString)
			}
		}
	}
	if encGpgId != "" {
		if base64 {
			encStr, err := Pass.EncryptData2String(&d.Buffer, &encGpgId)
			if err != nil {
				log.Println("Cannot encrypt data", err)
			} else {
				d.Buffer = []byte(encStr)
			}
		} else {
			encData, err := Pass.EncryptData(&d.Buffer, &encGpgId)
			if err != nil {
				log.Println("Cannot encrypt data", err)
			} else {
				d.Buffer = *encData
			}
		}
	}

	n, err := d.Flush()
	if err != nil {
		log.Println("Could not write data", err)
	} else {
		log.Printf("\nWrote %d bytes of data to %s", n, d.Destination)
	}
	log.Println("End of program")
}
