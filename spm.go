package spm

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dchest/uniuri"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

var (
	lettersAndNumbers             = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	lettersNumbersAndSpecialChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!@#$%^&*()-_+=")
)

type passwordDbInternals struct {
	data          map[string]string
	passwordNonce [32]byte
}

type PasswordDb struct {
	passwordDbInternals
	key          [32]byte
	keyWasInited bool
}

func NewPasswordDb() (*PasswordDb, error) {
	var passNonce [32]byte
	_, err := rand.Read(passNonce[:])
	if err != nil {
		return &PasswordDb{}, err
	}

	return &PasswordDb{
		passwordDbInternals: passwordDbInternals{
			data:          make(map[string]string),
			passwordNonce: passNonce,
		},
		keyWasInited: false,
	}, nil
}

func (p *PasswordDb) InitKeyFromPassword(password string) {
	passAndNonce := make([]byte, len(p.passwordNonce)+len(password))
	copy(passAndNonce[:len(p.passwordNonce)], p.passwordNonce[:])
	copy(passAndNonce[len(p.passwordNonce):], []byte(password))
	p.key = sha3.Sum256(passAndNonce)
	p.keyWasInited = true
}

func (p *PasswordDb) WriteToStorage(dir string) error {
	if !p.keyWasInited {
		return errors.New("Cannot write to storage with uninitialized key")
	}
	pwdDbJson, err := json.Marshal(p.data)
	if err != nil {
		return err
	}
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return err
	}

	ciphertext := secretbox.Seal(nil, pwdDbJson, &nonce, &(p.key))
	ciphAndNonce := make([]byte, len(p.passwordNonce)+len(nonce)+len(ciphertext))
	copy(ciphAndNonce[:len(p.passwordNonce)], p.passwordNonce[:])
	copy(ciphAndNonce[len(p.passwordNonce):(len(p.passwordNonce)+len(nonce))], nonce[:])
	copy(ciphAndNonce[(len(p.passwordNonce)+len(nonce)):], ciphertext)
	err = ioutil.WriteFile(dir+"/spm_db.bin", ciphAndNonce, 0600)
	return err
}

func (p *PasswordDb) LoadFromStorage(dir, masterPassword string) error {
	if _, err := os.Stat(dir + "/spm_db.bin"); os.IsNotExist(err) {
		return errors.New("Unable to access SPM directory or database file")
	}

	ciphAndNonce, err := ioutil.ReadFile(dir + "/spm_db.bin")

	if err != nil {
		return err
	}

	var nonce [24]byte
	copy(p.passwordNonce[:], ciphAndNonce[:len(p.passwordNonce)])
	p.InitKeyFromPassword(masterPassword)

	copy(nonce[:], ciphAndNonce[len(p.passwordNonce):(len(p.passwordNonce)+len(nonce))])
	ciphertext := make([]byte, len(ciphAndNonce)-len(nonce)-len(p.passwordNonce))
	copy(ciphertext, ciphAndNonce[(len(p.passwordNonce)+len(nonce)):])

	pwdDbJson, decryptSuccessful := secretbox.Open(nil, ciphertext, &nonce, &p.key)
	if !decryptSuccessful {
		return errors.New("Decryption of password DB failed")
	}
	err = json.Unmarshal(pwdDbJson, &(p.data))
	return err
}

func (p *PasswordDb) GetEntry(name string) (string, error) {
	if _, ok := p.data[name]; !ok {
		return "", errors.New(fmt.Sprintf("Entry %s not found in database.", name))
	} else {
		return p.data[name], nil
	}
}

func (p *PasswordDb) AddEntry(name, password string) error {
	if _, ok := p.data[name]; ok {
		return errors.New(fmt.Sprintf("Entry %s already exists. Delete first.", name))
	}
	p.data[name] = password
	return nil
}

func (p *PasswordDb) GenerateEntry(name string, length int, allowSpecialChars bool) error {
	if _, ok := p.data[name]; ok {
		return errors.New(fmt.Sprintf("Entry %s already exists. Delete first.", name))
	}
	var password string
	if allowSpecialChars {
		password = uniuri.NewLenChars(length, lettersNumbersAndSpecialChars)
	} else {
		password = uniuri.NewLenChars(length, lettersAndNumbers)
	}
	p.data[name] = password
	return nil
}

func (p *PasswordDb) RemoveEntry(name string) error {
	if _, ok := p.data[name]; !ok {
		return errors.New(fmt.Sprintf("Entry %s not found in database.", name))
	}
	delete(p.data, name)
	return nil
}

func (p *PasswordDb) GetListOfNames() string {
	result := make([]string, 0)
	for k, _ := range p.data {
		result = append(result, k)
	}
	sort.Strings(result)
	return strings.Join(result, "\n")
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}
