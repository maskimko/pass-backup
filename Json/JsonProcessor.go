package Json

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PasswordRecord struct {
	Password    string
	Login       string
	Url         string
	Email       string
	Description string //First line of comment
	Id          string //PasswordSafe/<category>/<title> for PasswordSafe or Pass/<pass path> for Pass
	Version     int8
	Notes       string //Rest of data
}

func New(password *string, login *string, url *string, email *string, desc *string, id *string, ver int8, notes *string) *PasswordRecord {
	return &PasswordRecord{
		Password:    *password,
		Login:       *login,
		Url:         *url,
		Email:       *email,
		Description: *desc,
		Version:     ver,
		Id:          *id,
		Notes:       *notes}

}

func NewFromPasswordSafe(password *string, login *string, url *string, email *string, desc *string, title *string, category *string, ver int8, notes *string) *PasswordRecord {
	return &PasswordRecord{
		Password:    *password,
		Login:       *login,
		Url:         *url,
		Email:       *email,
		Description: *desc,
		Version:     ver,
		Id:          fmt.Sprintf("PasswordSafe/%s/%s", *category, *title),
		Notes:       *notes}
}

func NewFromPass(password *string, login *string, url *string, email *string, desc *string, path *[]string, ver int8, notes *string) *PasswordRecord {
	return &PasswordRecord{
		Password:    *password,
		Login:       *login,
		Url:         *url,
		Email:       *email,
		Description: *desc,
		Version:     ver,
		Id:          fmt.Sprintf("Pass/%s", strings.Join(*path, "/")),
		Notes:       *notes}
}

func NewFromJson(jd *[]byte) (*PasswordRecord, error) {
	var pr PasswordRecord
	err := json.Unmarshal(*jd, &pr)
	if err != nil {
		fmt.Printf("Cannot deserialize string %s to PasswordRecord", string(*jd))
		return nil, err
	}
	return &pr, nil
}

func (pr *PasswordRecord) ToJson() *[]byte {
	jd, err := json.Marshal(pr)
	if err != nil {
		fmt.Printf("Cannot serialize password record id: %s", pr.Id)
		return nil
	}
	return &jd
}
