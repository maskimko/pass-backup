package PasswordSafe

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
)

type passwordSafeRecord struct {
	Title    string
	Category string
	Username string
	Password string
	Website  string
	Comments string
}

type fieldNumberError struct {
	reason string
}

func (e *fieldNumberError) Error() string {
	return e.reason
}

func ReadRecords(passwordsCsvFile string, delimeter *rune, comment *rune) ([]*passwordSafeRecord, error) {
	var passwords []*passwordSafeRecord = make([]*passwordSafeRecord, 0)
	pf, err := os.Open(passwordsCsvFile)
	defer pf.Close()
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(pf)
	if delimeter != nil {
		r.Comma = *delimeter
	}
	if comment != nil {
		r.Comment = *comment
	}
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) != 6 {
			return nil, &fieldNumberError{reason: "Cannot add to struct more than 6 fields"}
		}
		var psr passwordSafeRecord = passwordSafeRecord{Title: record[0], Category: record[1], Username: record[2], Password: record[3], Website: record[4], Comments: record[5]}
		fmt.Printf("%v\n", psr)
		passwords = append(passwords, &psr)
	}
	return passwords, nil
}
