package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI colors for the Hawk's vision
const (
	Red    = "\033[91m"
	Green  = "\033[92m"
	White  = "\033[97m"
	Yellow = "\033[93m"
	Cyan   = "\033[96m"
	Reset  = "\033[0m"
)

const (
	Version  = "1.0.0"
	TestHost = "57hakur.com"
)

var headersToTest = []map[string]string{
	{"Host": TestHost},
	{"X-Forwarded-Host": TestHost},
	{"X-Forwarded-Server": TestHost},
	{"X-Host": TestHost},
	{"Forwarded": "host=" + TestHost},
	{"X-HTTP-Host-Override": TestHost},
}

func printBanner() {
	banner := `
  _    _           _     _    _                _    
 | |  | |         | |   | |  | |              | |   
 | |__| | ___  ___| |_  | |__| | __ ___      _| | __
 |  __  |/ _ \/ __| __| |  __  |/ _` + "`" + ` \ \ /\ / / |/ /
 | |  | | (_) \__ \ |_  | |  | | (_| |\ V  V /|   < 
 |_|  |_|\___/|___/\__| |_|  |_|\__,_| \_/\_/ |_|\_\
                                         v` + Version

	fmt.Println(Cyan + banner + Reset)
	fmt.Println(Yellow + " [*] Hunting for Host Header Reflections..." + Reset)
	fmt.Println(strings.Repeat("-", 60))
}

func normalizeTarget(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	u, err := url.Parse(target)
	if err == nil && u.Scheme != "" {
		return []string{target}
	}
	return []string{"https://" + target, "http://" + target}
}

func checkReflection(client *http.Client, targetURL string, headers map[string]string) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Skip common noise status codes
	badStatus := map[int]bool{409: true, 500: true, 502: true, 404: true, 421: true}
	if badStatus[resp.StatusCode] {
		return
	}

	// 1. Check Headers for reflection
	foundInHeaders := false
	for k, v := range resp.Header {
		headerStr := k + ": " + strings.Join(v, ", ")
		if strings.Contains(headerStr, TestHost) {
			foundInHeaders = true
			break
		}
	}

	// 2. Check Body for reflection
	bodyBytes, _ := io.ReadAll(resp.Body)
	foundInBody := strings.Contains(string(bodyBytes), TestHost)

	if foundInBody || foundInHeaders {
		color := Green
		reflectedIn := "Headers"
		if foundInBody {
			color = Red
			reflectedIn = "Body"
		}

		fmt.Printf("%s[+] Reflection found! %s\n", color, targetURL)
		fmt.Printf("%s    Method      : %v\n", White, headers)
		fmt.Printf("    Status      : %d\n", resp.StatusCode)
		fmt.Printf("%s    Location    : %s%s\n", color, reflectedIn, Reset)
		fmt.Printf("%s%s%s\n", White, strings.Repeat("-", 50), Reset)
	}
}

func main() {
	printBanner()

	filePtr := flag.String("f", "", "File containing targets (one per line)")
	urlPtr := flag.String("u", "", "Single target URL or domain")
	concurrency := flag.Int("c", 20, "Number of concurrent workers")
	flag.Parse()

	if *filePtr == "" && *urlPtr == "" {
		fmt.Printf("%s[!] Usage: ./hosthawk -u example.com or -f targets.txt%s\n", Red, Reset)
		return
	}

	var targets []string
	if *filePtr != "" {
		file, err := os.Open(*filePtr)
		if err != nil {
			fmt.Printf("%s[-] Error reading file: %v%s\n", Red, err, Reset)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if t := strings.TrimSpace(scanner.Text()); t != "" {
				targets = append(targets, t)
			}
		}
	}
	if *urlPtr != "" {
		targets = append(targets, *urlPtr)
	}

	// Transport setup for security testing (ignores SSL errors)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   7 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, rawTarget := range targets {
		urls := normalizeTarget(rawTarget)
		for _, u := range urls {
			for _, h := range headersToTest {
				wg.Add(1)
				go func(target string, head map[string]string) {
					defer wg.Done()
					sem <- struct{}{}
					checkReflection(client, target, head)
					<-sem
				}(u, h)
			}
		}
	}

	wg.Wait()
	fmt.Printf("\n%s[*] Hunting complete.%s\n", Yellow, Reset)
}
