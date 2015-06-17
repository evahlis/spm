package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/dchest/uniuri"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"os"
	"os/user"
	"sort"
	"time"
)

var (
	storageDir          = flag.String("dir", ".spm", "Path relative to current user's home directory where data should be stored.")
	generatePassword    = flag.Int("gen", -1, "Set to the length of the password to be generated")
	listFlag            = flag.Bool("l", false, "List all available accounts")
	setFlag             = flag.Bool("set", false, "Enter password for new entry instead of generating it")
	deleteFlag          = flag.Bool("del", false, "Use this flag to delete an entry")
	printFlag           = flag.Bool("print", false, "Use this flag to print password to stdout instead of copying to clipboard")
	disableSpecialChars = flag.Bool("nosymbols", false, "Use this flag to disable usage of special characters when generating passwords")
	insecurePwdRead     = flag.Bool("pwdstdin", false, "If set, password will be directly read from STDIN. This should only be used if the process STDIN received piped inputs and not if the user is typing the password in.")

	LETTERS_AND_NUMBERS               = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	LETTERS_NUMBERS_AND_SPECIAL_CHARS = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!@#$%^&*()-_+=")
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

func NewPasswordDb() (PasswordDb, error) {
	var passNonce [32]byte
	_, err := rand.Read(passNonce[:])
	if err != nil {
		return PasswordDb{}, err
	}

	return PasswordDb{
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
		password = uniuri.NewLenChars(length, LETTERS_NUMBERS_AND_SPECIAL_CHARS)
	} else {
		password = uniuri.NewLenChars(length, LETTERS_AND_NUMBERS)
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

func (p *PasswordDb) GetListOfNames() []string {
	result := make([]string, 0)
	for k, _ := range p.data {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

func initSpmDirIfNotExists(spmDir, masterPassword string, promptForMasterPw bool) bool {
	if _, err := os.Stat(spmDir); !os.IsNotExist(err) {
		return false
	}
	err := os.MkdirAll(spmDir, 0700)
	panicError(err)
	pwDb, err := NewPasswordDb()
	panicError(err)
	if promptForMasterPw {
		fmt.Printf("Creating a new database.\nEnter master password: ")
		masterPassword = string(gopass.GetPasswd())
	}
	pwDb.InitKeyFromPassword(masterPassword)
	err = pwDb.WriteToStorage(spmDir)
	panicError(err)
	return true
}

func main() {
	flag.Parse()
	curUser, err := user.Current()
	spmDir := curUser.HomeDir + "/.spm"
	panicError(err)
	initSpmDirIfNotExists(spmDir, "", true)
	var pwDb PasswordDb

	var masterPassword string
	if !*insecurePwdRead {
		fmt.Printf("Enter the master password: ")
		masterPassword = string(gopass.GetPasswd())
	} else {
		fmt.Scan(&masterPassword)
	}

	err = pwDb.LoadFromStorage(spmDir, masterPassword)
	panicError(err)

	if *listFlag {
		names := pwDb.GetListOfNames()
		for _, name := range names {
			fmt.Println(name)
		}
		return
	}

	var serviceName string
	if flag.Arg(0) == "" {
		fmt.Println("Please enter at least one non-empty service name")
		return
	} else {
		serviceName = flag.Arg(0)
	}

	if !*deleteFlag && *generatePassword == -1 && !*setFlag {
		password, err := pwDb.GetEntry(serviceName)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		if !*printFlag {
			panicError(clipboard.WriteAll(password))
			fmt.Println("Copied password to clipboard")
			for i := 0; i < 6; i++ {
				fmt.Printf("Clearing in %d seconds...\n", 60-10*i)
				time.Sleep(10 * time.Second)
			}
			panicError(clipboard.WriteAll(""))
			fmt.Println("Clipboard cleared.")
		} else {
			fmt.Println(password)
		}
	} else if *generatePassword != -1 && !*deleteFlag && !*setFlag {
		err = pwDb.GenerateEntry(serviceName, *generatePassword, !*disableSpecialChars)
		pwDb.WriteToStorage(spmDir)
		panicError(err)
	} else if *setFlag && !*deleteFlag && *generatePassword == -1 {
		for _, name := range flag.Args() {
			fmt.Printf("Enter the password for [%s]: ", name)
			password1 := string(gopass.GetPasswd())
			fmt.Printf("Re-enter the password: ")
			password2 := string(gopass.GetPasswd())
			if password1 != password2 {
				fmt.Println("Passwords do not match. No changes made to DB.")
				return
			}
			pwDb.AddEntry(name, password1)
			pwDb.WriteToStorage(spmDir)
		}

	} else if !*setFlag && *deleteFlag && *generatePassword == -1 {
		err = pwDb.RemoveEntry(serviceName)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		pwDb.WriteToStorage(spmDir)
	} else {
		fmt.Println("Invalid flag combination. Run spm --help for help.")
	}
}
