package main

import (
	"code.google.com/p/rsc/qr"
	"flag"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/evahlis/spm"
	"github.com/fumiyas/qrc/lib"
	"github.com/fumiyas/qrc/tty"
	"github.com/howeyc/gopass"
	"github.com/mattn/go-colorable"
	"os"
	"os/user"
	"time"
)

var (
	storageDir          = flag.String("dir", ".spm", "Path relative to current user's home directory where data should be stored.")
	generatePassword    = flag.Int("gen", -1, "Set to the length of the password to be generated")
	listFlag            = flag.Bool("l", false, "List all available accounts")
	setFlag             = flag.Bool("set", false, "Enter password for new entry instead of generating it")
	deleteFlag          = flag.Bool("del", false, "Use this flag to delete an entry")
	printFlag           = flag.Bool("print", false, "Use this flag to print password to stdout instead of copying to clipboard")
	qrFlag              = flag.Bool("qr", false, "Print the password as an ANSI QR code to the terminal")
	disableSpecialChars = flag.Bool("nosymbols", false, "Use this flag to disable usage of special characters when generating passwords")
	insecurePwdRead     = flag.Bool("pwdstdin", false, "If set, password will be directly read from STDIN. This should only be used if the process STDIN received piped inputs and not if the user is typing the password in.")
)

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
	pwDb, err := spm.NewPasswordDb()
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

func printQr(text string) {
	code, _ := qr.Encode(text, qr.L)
	da1, err := tty.GetDeviceAttributes1(os.Stdout)
	if err == nil && da1[tty.DA1_SIXEL] {
		qrc.PrintSixel(os.Stdout, code, false)
	} else {
		stdout := colorable.NewColorableStdout()
		qrc.PrintAA(stdout, code, false)
	}
}

func main() {
	flag.Parse()
	curUser, err := user.Current()
	spmDir := curUser.HomeDir + "/.spm"
	panicError(err)
	initSpmDirIfNotExists(spmDir, "", true)
	var pwDb spm.PasswordDb

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
		fmt.Print(names)
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
		if !*printFlag && !*qrFlag {
			panicError(clipboard.WriteAll(password))
			fmt.Println("Copied password to clipboard")
			for i := 0; i < 6; i++ {
				fmt.Printf("Clearing in %d seconds...\n", 60-10*i)
				time.Sleep(10 * time.Second)
			}
			panicError(clipboard.WriteAll(""))
			fmt.Println("Clipboard cleared.")
		} else if *qrFlag {
			fmt.Println("The password encoded as a QR code:")
			printQr(password)
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
