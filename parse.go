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

func main() {

	optEmailId := getopt.StringLong("email", 'e', "", "Your PGP identity email address")
	optPassPrefix := getopt.StringLong("prefix", 'p', "/", "Which directory in password store should be considered as entry point")
	optPasswordSafeFile := getopt.StringLong("passwordSafe", 'P', "", "Exported CSV file with PasswordSafe data")
	helpFlag := getopt.Bool('?', "Display help")
	getopt.Parse()
	if *helpFlag {
		getopt.Usage()
		os.Exit(0)
	}

	//Obtain the passphrase
	log.Printf("Input the passphrase: ")
	passphrase, err := gopass.GetPasswd()
	if err != nil {
		log.Fatal(err)
	}

	var creds *Pass.GpgCredentilas = &Pass.GpgCredentilas{EmailId: *optEmailId, Passphrase: string(passphrase)}
	precs, err := Pass.GetPassRecords(*optPassPrefix, creds)
	if err != nil {
		log.Println("Cannot get Pass passwords", err)
	}
	for i := range precs {
		fmt.Printf("Pass record:\n\t%v\n", *precs[i])
	}

	if optPasswordSafeFile != nil && *optPasswordSafeFile != "" {
		PasswordSafe.ReadRecords(*optPasswordSafeFile, nil, nil)
	}

	log.Println("End of program")
}
