package Pass

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const passwordStore = ".password-store"

type fileDataMap struct {
	fileName string
	data     *[]byte
}

type gpgError struct {
	message string
}

func (e *gpgError) Error() string {
	return e.message
}

type incorrectKeyError struct {
	emailId string
}

func (ie *incorrectKeyError) Error() string {
	return fmt.Sprintf("This data is not encrypted with key %s", ie.emailId)
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
	var wg sync.WaitGroup
	sdchan := make(chan *fileDataMap)
	wg.Add(len(*fileNames))
	var secretData []fileDataMap = make([]fileDataMap, 0)

	for i := range *fileNames {
		go func(fn string) {
			defer wg.Done()
			dat, err := ioutil.ReadFile(fn)
			if err != nil {
				log.Println("Cannot read file contents:", fn)
			} else {
				sdchan <- &fileDataMap{fileName: fn, data: &dat}
			}
		}((*fileNames)[i])
	}
	go func() {
		for i := range sdchan {
			secretData = append(secretData, *i)
		}
	}()
	wg.Wait()
	close(sdchan)

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
			err = &gpgError{fmt.Sprintf("Cannot decrypt file %s\nDetails: %v\n", fdm.fileName, err)}
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
		return nil, err
	}
	dataMap := readSecretData(pf)
	decData, err := parseSecretData(dataMap, creds)
	if err != nil {
		log.Printf("Was not able to decrypt password files. %v", err)
		return nil, err
	}
	for i := range decData {
		fmt.Printf("Pass record:\n\t%v\n", *decData[i])
	}
	return decData, nil
}
