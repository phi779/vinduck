package browserdata

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/moond4rk/hackbrowserdata/extractor"
)

type outPutter struct {
	format string
}

func newOutPutter(flag string) *outPutter {
	return &outPutter{
		format: flag,
	}
}

func (o *outPutter) Write(data extractor.Extractor, writer io.Writer) error {
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Len() > 0 {
		elem := val.Index(0)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		typeName := strings.ToLower(elem.Type().String())

		if strings.Contains(typeName, "password") {
			return o.writePasswordFormat(val, writer)
		} else if strings.Contains(typeName, "card") || strings.Contains(typeName, "credit") {
			return o.writeCreditCardFormat(val, writer)
		}
	}

	switch o.format {
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		return encoder.Encode(data)
	case "txt":
		return o.writeFormattedText(data, writer)
	default:
		gocsv.SetCSVWriter(func(w io.Writer) *gocsv.SafeCSVWriter {
			writer := csv.NewWriter(transform.NewWriter(w, unicode.UTF8BOM.NewEncoder()))
			writer.Comma = ','
			return gocsv.NewSafeCSVWriter(writer)
		})
		return gocsv.Marshal(data, writer)
	}
}

func (o *outPutter) writeCreditCardFormat(val reflect.Value, writer io.Writer) error {
	for i := 0; i < val.Len(); i++ {
		elem := val.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		var guid, name, month, year, number, address, nickname string

		if f := elem.FieldByName("GUID"); f.IsValid() {
			guid = f.String()
		}
		if f := elem.FieldByName("Name"); f.IsValid() {
			name = f.String()
		}
		if f := elem.FieldByName("ExpirationMonth"); f.IsValid() {
			month = f.String()
		}
		if f := elem.FieldByName("ExpirationYear"); f.IsValid() {
			year = f.String()
		}
		if f := elem.FieldByName("CardNumber"); f.IsValid() {
			number = f.String()
		}
		if f := elem.FieldByName("Address"); f.IsValid() {
			address = f.String()
		}
		if f := elem.FieldByName("NickName"); f.IsValid() {
			nickname = f.String()
		}

		if number == "" {
			continue
		}

		cardLine := fmt.Sprintf("GUID: %s\nName: %s\nCard Number: %s\nExpiration: %s/%s\nAddress: %s\nNickname: %s\n=====================\n",
			guid,
			name,
			number,
			month,
			year,
			address,
			nickname,
		)

		if _, err := writer.Write([]byte(cardLine)); err != nil {
			return err
		}
	}
	return nil
}

func (o *outPutter) writePasswordFormat(val reflect.Value, writer io.Writer) error {
	for i := 0; i < val.Len(); i++ {
		elem := val.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		var loginURL, username, password string
		var createDate time.Time

		if f := elem.FieldByName("LoginURL"); f.IsValid() {
			loginURL = f.String()
		}
		if f := elem.FieldByName("UserName"); f.IsValid() {
			username = f.String()
		}
		if f := elem.FieldByName("Password"); f.IsValid() {
			password = f.String()
		}
		if f := elem.FieldByName("CreateDate"); f.IsValid() && f.Type().String() == "time.Time" {
			createDate = f.Interface().(time.Time)
		}

		if username == "" || password == "" {
			continue
		}

		passLine := fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\nCreateDate: %s\n=====================\n",
			loginURL,
			username,
			password,
			createDate.Format("2006-01-02 15:04:05"),
		)

		if _, err := writer.Write([]byte(passLine)); err != nil {
			return err
		}
	}
	return nil
}

func (o *outPutter) writeFormattedText(data extractor.Extractor, writer io.Writer) error {
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Slice {
		return fmt.Errorf("expected slice, got %v", val.Kind())
	}

	if val.Len() > 0 {
		elem := val.Index(0)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		typ := elem.Type()

		if strings.Contains(strings.ToLower(typ.Name()), "cookie") {
			return o.Writecook(val, writer)
		} else {
			return o.writeDefaultFormat(val, writer)
		}
	}
	return nil
}

func (o *outPutter) Writecook(val reflect.Value, writer io.Writer) error {
	for i := 0; i < val.Len(); i++ {
		elem := val.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		var (
			host, path, name, value string
			expiry                  int64
			secure                  bool
		)

		if f := elem.FieldByName("KeyName"); f.IsValid() {
			name = f.String()
			if name == "" {
				continue
			}
		} else {
			continue
		}

		if f := elem.FieldByName("Host"); f.IsValid() {
			host = f.String()
		}
		if f := elem.FieldByName("Path"); f.IsValid() {
			path = f.String()
		}
		if f := elem.FieldByName("Value"); f.IsValid() {
			value = f.String()
		}
		if f := elem.FieldByName("Expires"); f.IsValid() {
			expiry = f.Int()
		}
		if f := elem.FieldByName("IsSecure"); f.IsValid() {
			secure = f.Bool()
		}

		cookieLine := fmt.Sprintf("%s\tTRUE\t%s\t%t\t%d\t%s\t%s\n",
			host,
			path,
			secure,
			expiry,
			name,
			value,
		)

		if _, err := writer.Write([]byte(cookieLine)); err != nil {
			return err
		}
	}
	return nil
}

func (o *outPutter) writeDefaultFormat(val reflect.Value, writer io.Writer) error {
	if val.Len() == 0 {
		return nil
	}

	elem := val.Index(0)
	if elem.Kind() == reflect.Ptr {
		elem = elem.Elem()
	}

	if elem.Kind() != reflect.Struct {
		return nil
	}

	typ := elem.Type()
	var headers []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.IsExported() {
			headers = append(headers, field.Name)
		}
	}

	if err := o.writeLine(writer, headers); err != nil {
		return err
	}

	for i := 0; i < val.Len(); i++ {
		elem := val.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		var row []string
		for i := 0; i < elem.NumField(); i++ {
			field := elem.Field(i)
			if field.CanInterface() {
				row = append(row, fmt.Sprintf("%v", field.Interface()))
			}
		}

		if err := o.writeLine(writer, row); err != nil {
			return err
		}
	}

	return nil
}

func (o *outPutter) writeLine(writer io.Writer, fields []string) error {
	line := strings.Join(fields, ",") + "\n"
	_, err := writer.Write([]byte(line))
	return err
}

func (o *outPutter) CreateFile(dir, filename string) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	rootDir := `C:\Users\Public`

	var subDir string
	switch {
	case strings.Contains(strings.ToLower(filename), "cookie"):
		subDir = filepath.Join(hostname, "Cookie")
	case strings.Contains(strings.ToLower(filename), "password"):
		subDir = filepath.Join(hostname, "Password")
	case strings.Contains(strings.ToLower(filename), "creditcard"),
		strings.Contains(strings.ToLower(filename), "card"),
		strings.Contains(strings.ToLower(filename), "credit"):
		subDir = filepath.Join(hostname, "CreditCard")
	default:
		subDir = hostname
	}

	fullDir := filepath.Join(rootDir, subDir)

	// Create parent directories if they don't exist
	if err := os.MkdirAll(fullDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %v", fullDir, err)
	}

	// Create or open the file
	p := filepath.Join(fullDir, filename)
	file, err := os.OpenFile(filepath.Clean(p), os.O_TRUNC|os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create/open file %s: %v", p, err)
	}

	return file, nil
}
func (o *outPutter) Ext() string {
	return o.format
}
