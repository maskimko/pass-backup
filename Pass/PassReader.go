package Pass

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const passwordStore = ".password-store"

type fileDataMap struct {
	fileName string
	data     *[]byte
}

type gpgError struct {
	message string
}

func getUserDir() string {
	//Will work on UNIX systems only
	var home string = os.Getenv("HOME")
	return home
}

func (e *gpgError) Error() string {
	return e.message
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

func readSecretData(fileNames *[]string) *[]fileDataMap {
	var secretData []fileDataMap = make([]fileDataMap, len(*fileNames))
	for i := range *fileNames {
		dat, err := ioutil.ReadFile((*fileNames)[i])
		if err != nil {
			log.Println("Cannot read file contents:", (*fileNames)[i])
		}
		secretData[i] = fileDataMap{fileName: (*fileNames)[i], data: &dat}
	}
	return &secretData
}

func getPassFiles(passPrefix string) (*[]string, error) {
	//Get list of pass files starting from prefix directory
	passHomeRef := checkGnuPass(getUserDir())
	if passHomeRef == nil {
		return nil, &gpgError{"Cannot find GNU Pass store"}
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
	passwords := make([]string, 0, 10)
	err := filepath.Walk(entryPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Handling error while accessing path %q: %v\n", entryPoint, err)
		}
		if info.IsDir() && info.Name() == ".git" {
			log.Println("Skipping Git directory")
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(path, ".gpg") {
			passwords = append(passwords, path)
		}
		return nil
	})
	if err != nil {
		log.Println("Error while walking the password store", err)
		return nil, err
	}
	return &passwords, nil
}

func parseLocation(path string) *[]string {
	sp := strings.Split(path, ".password-store/")
	if len(sp) != 2 {
		log.Println("Cannot split password path ", path)
		return nil
	}
	tokens := strings.Split(sp[1], "/")
	return &tokens
}

func parseSecretData(data *[]fileDataMap, creds *GpgCredentilas) ([]*PassRecord, error) {
	var pra []*PassRecord = make([]*PassRecord, len(*data))
	for i := range *data {
		var fdm fileDataMap = (*data)[i]
		decData, err := decrypt(fdm.data, creds)
		if err != nil {
			log.Println("Cannot decrypt", err)
			return pra, err
		}
		passRecord, err := Parse(decData, parseLocation(fdm.fileName))
		if err != nil {
			log.Printf("Cannot parse decrypted data. Details: %s", err)
			return pra, err
		}
		pra[i] = passRecord
	}
	return pra, nil
}

func GetPassRecords(prefix string, creds *GpgCredentilas) ([]*PassRecord, error) {
	pf, err := getPassFiles(prefix)
	if err != nil {
		log.Printf("Was not able to get password files %v", err)
	}
	dataMap := readSecretData(pf)
	decData, err := parseSecretData(dataMap, creds)
	for i := range decData {
		fmt.Printf("Pass record:\n\t%v\n", *decData[i])
	}
	return decData, nil
}
