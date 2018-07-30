package main

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"

	"github.com/howeyc/gopass"
	"github.com/pborman/getopt"
	"golang.org/x/crypto/openpgp"
)

const mySecretString = "this is so very secret"
const prefix = "/home/maskimko/"
const secretKeyring = prefix + ".gnupg/secring.gpg"
const publicKeyring = prefix + ".gnupg/pubring.gpg"
const myEmail = "mshkolnyi@intellias.com"

type gpgError struct {
	message string
}

func (e *gpgError) Error() string {
	return e.message
}

func listEntities(entities []*openpgp.Entity) {
	var e openpgp.Entity
	for i := range entities {
		e = *entities[i]
		log.Printf("Key ID: %x\n", e.PrimaryKey.KeyId)
		for k, v := range e.Identities {
			log.Printf("\t%s: %v\n", k, v)
		}
	}
}

func getEntityByEmail(entities []*openpgp.Entity, email *string) []*openpgp.Entity {
	if email == nil || *email == "" {
		log.Println("Empty gpg identity query")
		return nil
	}
	for i := range entities {
		e := *entities[i]
		for k := range e.Identities {
			id := e.Identities[k]
			if id.UserId.Email == *email {
				ents := make([]*openpgp.Entity, 1)
				ents[0] = &e
				return ents
			}
		}
	}
	return nil
}

func encTest(secretString string) (string, error) {
	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	listEntities(entityList)
	var mail string
	mail = myEmail
	myList := getEntityByEmail(entityList, &mail)
	listEntities(myList)
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, myList, nil, nil, nil)
	if err != nil {
		return "", err
	}

	_, err = w.Write([]byte(mySecretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	log.Println("Encrypted secret: ", encStr)
	return encStr, nil
}

func enc(secretString string, emailId *string) (string, error) {
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	myList := getEntityByEmail(entityList, emailId)
	if myList == nil {
		err := &gpgError{"There is no such key with provided identity email: \"" + *emailId + "\""}
		return "", err
	}
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, myList, nil, nil, nil)
	if err != nil {
		return "", err
	}

	_, err = w.Write([]byte(mySecretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	return encStr, nil
}

func decTest(encString string, passphrase string) (string, error) {
	log.Println("Secret Keyring:", secretKeyring)
	log.Println("Passphrase:", passphrase)

	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private keys using passphrase")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)
	return decStr, nil
}

func main() {
	optEmailId := getopt.StringLong("email", 'e', "", "Your PGP identity email address")
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

	encStr, err := enc(mySecretString, optEmailId)
	if err != nil {
		log.Fatal(err)
	}
	decStr, err := decTest(encStr, string(passphrase))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Decrypted Secret:", decStr)
	log.Println("End of program")
}
