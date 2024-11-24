package types

import (
	"fmt"
	"os"
	"path/filepath"
)

type DataType int

const (
	ChromiumKey DataType = iota
	ChromiumPassword
	ChromiumCookie
	ChromiumBookmark
	ChromiumHistory
	ChromiumDownload
	ChromiumCreditCard
	ChromiumLocalStorage
	ChromiumSessionStorage
	ChromiumExtension

	YandexPassword
	YandexCreditCard

	FirefoxKey4
	FirefoxPassword
	FirefoxCookie
	FirefoxBookmark
	FirefoxHistory
	FirefoxDownload
	FirefoxCreditCard
	FirefoxLocalStorage
	FirefoxSessionStorage
	FirefoxExtension
)

var itemFileNames = map[DataType]string{
	ChromiumKey:            fileChromiumKey,
	ChromiumPassword:       fileChromiumPassword,
	ChromiumCookie:         fileChromiumCookie,
	ChromiumBookmark:       fileChromiumBookmark,
	ChromiumDownload:       fileChromiumDownload,
	ChromiumLocalStorage:   fileChromiumLocalStorage,
	ChromiumSessionStorage: fileChromiumSessionStorage,
	ChromiumCreditCard:     fileChromiumCredit,
	ChromiumExtension:      fileChromiumExtension,
	ChromiumHistory:        fileChromiumHistory,
	YandexPassword:         fileYandexPassword,
	YandexCreditCard:       fileYandexCredit,
	FirefoxKey4:            fileFirefoxKey4,
	FirefoxPassword:        fileFirefoxPassword,
	FirefoxCookie:          fileFirefoxCookie,
	FirefoxBookmark:        fileFirefoxData,
	FirefoxDownload:        fileFirefoxData,
	FirefoxLocalStorage:    fileFirefoxLocalStorage,
	FirefoxHistory:         fileFirefoxData,
	FirefoxExtension:       fileFirefoxExtension,
	FirefoxSessionStorage:  UnsupportedItem,
	FirefoxCreditCard:      UnsupportedItem,
}

func (i DataType) Filename() string {
	if fileName, ok := itemFileNames[i]; ok {
		return fileName
	}
	return UnsupportedItem
}

func (i DataType) TempFilename() string {
	const tempSuffix = "temp"
	tempFile := fmt.Sprintf("%s_%d.%s", i.Filename(), i, tempSuffix)
	return filepath.Join(os.TempDir(), tempFile)
}

func (i DataType) IsSensitive() bool {
	switch i {
	case ChromiumKey, ChromiumCookie, ChromiumPassword,
		FirefoxKey4, FirefoxPassword, FirefoxCookie, ChromiumCreditCard, FirefoxCreditCard, YandexCreditCard,
		YandexPassword:
		return true
	default:
		return false
	}
}

func FilterSensitiveItems(items []DataType) []DataType {
	var filtered []DataType
	for _, item := range items {
		if item.IsSensitive() {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// DefaultChromiumTypes returns only password and cookie items
var DefaultChromiumTypes = []DataType{
	ChromiumKey,
	ChromiumPassword,
	ChromiumCookie,
	ChromiumCreditCard, // Thêm dòng này

}

// DefaultFirefoxTypes returns only password and cookie items
var DefaultFirefoxTypes = []DataType{
	FirefoxKey4,
	FirefoxPassword,
	FirefoxCookie,
	FirefoxCreditCard,
}

// DefaultYandexTypes returns only password and cookie items
var DefaultYandexTypes = []DataType{
	ChromiumKey,
	ChromiumCookie,
	YandexPassword,
	YandexCreditCard, // Thêm dòng này

}

const (
	fileChromiumKey            = "Local State"
	fileChromiumCredit         = "Web Data"
	fileChromiumPassword       = "Login Data"
	fileChromiumHistory        = "History"
	fileChromiumDownload       = "History"
	fileChromiumCookie         = "Cookies"
	fileChromiumBookmark       = "Bookmarks"
	fileChromiumLocalStorage   = "Local Storage/leveldb"
	fileChromiumSessionStorage = "Session Storage"
	fileChromiumExtension      = "Secure Preferences"

	fileYandexPassword = "Ya Passman Data"
	fileYandexCredit   = "Ya Credit Cards"

	fileFirefoxKey4         = "key4.db"
	fileFirefoxCookie       = "cookies.sqlite"
	fileFirefoxPassword     = "logins.json"
	fileFirefoxData         = "places.sqlite"
	fileFirefoxLocalStorage = "webappsstore.sqlite"
	fileFirefoxExtension    = "extensions.json"

	UnsupportedItem = "unsupported item"
)
