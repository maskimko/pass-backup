package main

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"path/filepath"

	"github.com/howeyc/gopass"
	"github.com/pborman/getopt"
	"golang.org/x/crypto/openpgp"
)

const mySecretString = "this is so very secret"
const prefix = "/home/maskimko/"
const secretKeyring = prefix + ".gnupg/secring.gpg"
const publicKeyring = prefix + ".gnupg/pubring.gpg"
const myEmail = "mshkolnyi@intellias.com"
const passwordStore = ".password-store"

type gpgError struct {
	message string
}

func (e *gpgError) Error() string {
	return e.message
}

type gpgCredentilas struct {
	emailId    string
	passphrase string
}

func decrypt(data *[]byte, creds *gpgCredentilas) (string, error) {
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
	entity = getEntityByEmail(entityList, &creds.emailId)
	if entity == nil {
		err := &gpgError{"There is no such key with provided identity email: \"" + creds.emailId + "\""}
		return "", err
	}
	passphraseByte := []byte(creds.passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	messageDetails, err := openpgp.ReadMessage(bytes.NewBuffer(*data), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(messageDetails.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decData := string(bytes)
	return decData, nil
}

func readSecretData(fileNames []*string) []*[]byte {
	var secretData []*[]byte = make([]*[]byte, len(fileNames))
	for i := range fileNames {
		dat, err := ioutil.ReadFile(*fileNames[i])
		if err != nil {
			log.Println("Cannot read file contents:", *fileNames[i])
		}
		secretData[i] = &dat
	}
	return secretData
}

func listSecretData(data []*[]byte, creds *gpgCredentilas) {
	for i := range data {
		decData, err := decrypt(data[i], creds)
		if err != nil {
			log.Println("Cannot decrypt", err)
		}
		log.Println(decData)
	}
}

func getUserDir() string {
	//Will work on UNIX systems only
	var home string = os.Getenv("HOME")
	return home
}

func checkGnuPass(userDir string) *string {
	//returns referense for normalized path of GNU pass password storage if exists
	//otherwise returns nil
	var passHome string = userDir
	if !strings.HasSuffix(passHome, "/") {
		passHome = passHome + "/"
	}
	passHome = passHome + passwordStore
	fi, err := os.Stat(passHome)
	if os.IsNotExist(err) {
		log.Println("Cannot find GNU Pass store", err)
		return nil
	}
	if !fi.IsDir() {
		log.Println("GNU Pass store is not a directory!")
		return nil
	}
	return &passHome
}

func getPassFiles(passPrefix string) ([]*string, error) {
	//Get list of pass files starting from prefix directory
	passHomeRef := checkGnuPass(getUserDir())
	if passHomeRef == nil {
		return make([]*string, 0), &gpgError{"Cannot find GNU Pass store"}
	}
	var entryPoint string = *passHomeRef
	if !strings.HasSuffix(entryPoint, "/") {
		entryPoint = entryPoint + "/"
	}
	if passPrefix != "" {
		entryPoint = entryPoint + passPrefix
		if _, err := os.Stat(entryPoint); os.IsNotExist(err) {
			log.Printf("Cannot find directory specified by prefix %s. %s", passPrefix, err)
			return nil, err
		}
	}
	passwords := make([]*string, 0, 10)
	err := filepath.Walk(entryPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Handling error while accessing path %q: %v\n", entryPoint, err)
		}
		if info.IsDir() && info.Name() == ".git" {
			log.Println("Skipping Git directory")
			return filepath.SkipDir
		}
		if !info.IsDir() {
			passwords = append(passwords, &path)
		}
		return nil
	})
	if err != nil {
		log.Println("Error while walking the password store", err)
		return passwords, err
	}
	return passwords, nil
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

func getEntityByEmail(entities []*openpgp.Entity, email *string) *openpgp.Entity {
	if email == nil || *email == "" {
		log.Println("Empty gpg identity query")
		return nil
	}
	for i := range entities {
		e := *entities[i]
		for k := range e.Identities {
			id := e.Identities[k]
			if id.UserId.Email == *email {
				return &e
			}
		}
	}
	return nil
}

func enc(secretString string, emailId *string) (string, error) {
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity := getEntityByEmail(entityList, emailId)
	if entity == nil {
		err := &gpgError{"There is no such key with provided identity email: \"" + *emailId + "\""}
		return "", err
	}
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, []*openpgp.Entity{entity}, nil, nil, nil)
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
	optPassPrefix := getopt.StringLong("prefix", 'p', "/", "Which directory in password store should be considered as entry point")
	helpFlag := getopt.Bool('?', "Display help")
	getopt.Parse()
	if *helpFlag {
		getopt.Usage()
		os.Exit(0)
	}
	passes, err := getPassFiles(*optPassPrefix)
	if err != nil {
		log.Fatal(err)
	}

	//Obtain the passphrase
	log.Printf("Input the passphrase: ")
	passphrase, err := gopass.GetPasswd()
	if err != nil {
		log.Fatal(err)
	}

	var creds *gpgCredentilas = &gpgCredentilas{emailId: *optEmailId, passphrase: string(passphrase)}
	encStr, err := enc(mySecretString, optEmailId)
	if err != nil {
		log.Fatal(err)
	}
	decStr, err := decTest(encStr, string(passphrase))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Decrypted Secret:", decStr)

	encData := readSecretData(passes)
	listSecretData(encData, creds)

	log.Println("End of program")
}
