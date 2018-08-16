package Pass

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

// const secretKeyring = prefix + ".gnupg/secring.gpg"
// const publicKeyring = prefix + ".gnupg/pubring.gpg"

type GpgCredentilas struct {
	EmailId    string
	Passphrase string
}

func getUserDir() string {
	//Will work on UNIX systems only
	var home string = os.Getenv("HOME")
	return home
}

func getSecRing() string {
	return getUserDir() + "/.gnupg/secring.gpg"
}

func getPubRing() string {
	return getUserDir() + "/.gnupg/pubring.gpg"
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

func decrypt(data *[]byte, creds *GpgCredentilas) (*string, error) {
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	keyringFileBuffer, err := os.Open(getSecRing())
	if err != nil {
		return nil, err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, err
	}
	entity = getEntityByEmail(entityList, &creds.EmailId)
	if entity == nil {
		err := &gpgError{"There is no such key with provided identity email: \"" + creds.EmailId + "\""}
		return nil, err
	}
	passphraseByte := []byte(creds.Passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	messageDetails, err := openpgp.ReadMessage(bytes.NewBuffer(*data), entityList, nil, nil)
	if err != nil {
		if err.Error() == "openpgp: incorrect key" {

			return nil, &incorrectKeyError{creds.EmailId}
		}
		return nil, err
	}
	bytes, err := ioutil.ReadAll(messageDetails.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	decData := string(bytes)
	return &decData, nil
}
