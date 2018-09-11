package Pass

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"
)

type encryptionError struct {
	message string
	err     error
}

func (ee *encryptionError) Error() string {
	return fmt.Sprintf("%s (Details: %s)", ee.message, ee.err)
}

func EncryptData(data *[]byte, gpgId *string) (*[]byte, error) {
	keyringFileBuffer, _ := os.Open(getPubRing())
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, &encryptionError{"Cannot read the keyring", err}
	}
	entity := getEntityByEmail(entityList, gpgId)
	if entity == nil {
		err := &gpgError{"There is no such key with provided identity email: \"" + *gpgId + "\""}
		return nil, err
	}
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, &encryptionError{"Cannot encrypt the data", err}
	}
	_, err = w.Write(*data)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}
	return &bytes, nil
}

func EncryptData2String(data *[]byte, gpgId *string) (string, error) {
	bytes, err := EncryptData(data, gpgId)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(*bytes)
	return encStr, nil
}
