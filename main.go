package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// read the ./identifiants.txt file
	username, password := getCreds()

	client := &Client{
		LoginURL:            "https://controller.access.network/portal_api.php",
		LoginUsername:       username,
		LoginPassword:       password,
		PingIntervalSeconds: 50,
	}
	client.Login()
	client.StartTicking()

	// Wait here until CTRL-C or other term signal is received.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	client.Logout()
}

func getCreds() (string, string) {
	var username, password string

	// Check if WIFI_CREDS environment variable is set
	if creds, ok := os.LookupEnv("WIFI_CREDS"); ok {
		lines := strings.Split(creds, "\n")
		if len(lines) >= 2 {
			username, password = lines[0], lines[1]
		} else {
			log.Fatal("Invalid WIFI_CREDS format")
		}
	} else {
		// Read from identifiants.txt file
		file, err := os.Open("identifiants.txt")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			username = scanner.Text()
		} else {
			log.Fatal("Error reading username from file")
		}

		if scanner.Scan() {
			password = scanner.Text()
		} else {
			log.Fatal("Error reading password from file")
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
	return username, password
}

// =================================================================================================
// =======================          CLIENT CODE                                    	================
// =================================================================================================

type LoginResponse struct {
	// AuthenticateStep any    `json:"authenticate_step"`
	// AuthenticateType any    `json:"authenticate_type"`
	Step string `json:"step"`
	Type string `json:"type"`
	User struct {
		Login struct {
			Value string `json:"value"`
		} `json:"login"`
		PasswordDigest struct {
			Value string `json:"value"`
		} `json:"passwordDigest"`
		IPAddress struct {
			Value string `json:"value"`
		} `json:"ipAddress"`
		Profile struct {
			Value string `json:"value"`
		} `json:"profile"`
		Services struct {
			Value string `json:"value"`
		} `json:"services"`
		AutoDisconnect struct {
			Value bool `json:"value"`
		} `json:"autoDisconnect"`
		Schedule struct {
			Value []struct {
				Begin struct {
					Day  string `json:"day"`
					Hour string `json:"hour"`
					Min  string `json:"min"`
				} `json:"begin"`
				End struct {
					Day  string `json:"day"`
					Hour string `json:"hour"`
					Min  string `json:"min"`
				} `json:"end"`
			} `json:"value"`
		} `json:"schedule"`
		Validity struct {
			Value string `json:"value"`
		} `json:"validity"`
		InitTimeGMT struct {
			Value string `json:"value"`
		} `json:"initTimeGMT"`
		TimeCredit struct {
			Value     string `json:"value"`
			Remaining struct {
				Value int `json:"value"`
			} `json:"remaining"`
			Reneweach struct {
				Value string `json:"value"`
			} `json:"reneweach"`
			InitialRemaining struct {
				Value int `json:"value"`
			} `json:"initialRemaining"`
		} `json:"timeCredit"`
		IncomingNetwork struct {
			Value string `json:"value"`
		} `json:"incomingNetwork"`
		IncomingNetworkID struct {
			Value string `json:"value"`
		} `json:"incomingNetworkID"`
		IncomingZone struct {
			Value string `json:"value"`
		} `json:"incomingZone"`
		IncomingVlan struct {
			Value string `json:"value"`
		} `json:"incomingVlan"`
		IncommingVlan struct {
			Value string `json:"value"`
		} `json:"incommingVlan"`
		IncommingZone struct {
			Value string `json:"value"`
		} `json:"incommingZone"`
		Multidevice struct {
			Value string `json:"value"`
		} `json:"multidevice"`
		UniversalTime struct {
			Value int `json:"value"`
		} `json:"universalTime"`
		TimezoneOffset struct {
			Value string `json:"value"`
		} `json:"timezoneOffset"`
		RequestedURL struct {
			Value string `json:"value"`
		} `json:"requestedURL"`
		AllowModPwdBySelf  bool `json:"allowModPwdBySelf"`
		GetPurchaseSummary struct {
			Show bool `json:"show"`
		} `json:"getPurchaseSummary"`
	} `json:"user"`
}

type Client struct {
	LoginURL            string
	LoginUsername       string
	LoginPassword       string
	PingIntervalSeconds int
	passwordDigest      string
}

func (c *Client) newUnsecureHTTPClient() *http.Client {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
	// Create a new HTTP client with the TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client
}

func (c *Client) Login() error {
	client := c.newUnsecureHTTPClient()

	body := []byte(fmt.Sprintf(`action=authenticate&login=%s&password=%s&policy_accept=false`, url.QueryEscape(c.LoginUsername), url.QueryEscape(c.LoginPassword)))

	r, err := http.NewRequest("POST", c.LoginURL, bytes.NewBuffer(body))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return err
	}

	if resp.StatusCode != 200 {
		fmt.Println("[login] Error response status code:", resp.StatusCode)
		fmt.Println("[login] Response body:", string(bodyBytes))
		return fmt.Errorf("[login] Error response status code: %d", resp.StatusCode)
	}

	var loginResponse LoginResponse
	err = json.Unmarshal(bodyBytes, &loginResponse)
	if err != nil {
		fmt.Println("Error unmarshalling response:", err)
		return err
	}
	// check that the stuff is actually defined till the password digest
	c.passwordDigest = loginResponse.User.PasswordDigest.Value

	if c.passwordDigest == "" {
		fmt.Println("Incorrect credentials")
		return errors.New("invalid credentials")
	}

	fmt.Printf("Response: %+v\n", loginResponse)
	return nil
}

func (c *Client) Ping() error {
	fmt.Println("Pinging...")
	client := c.newUnsecureHTTPClient()

	body := []byte(fmt.Sprintf(`action=refresh&login=%s&password_digest=%s&policy_accept=false`, url.QueryEscape(c.LoginUsername), url.QueryEscape(c.passwordDigest)))

	r, err := http.NewRequest("POST", c.LoginURL, bytes.NewBuffer(body))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading body:", err)
			return err
		}

		fmt.Println("[pinging] Error response status code:", resp.StatusCode)
		fmt.Println("[pinging] Response body:", string(bodyBytes))
		return fmt.Errorf("[pinging] Error response status code: %d", resp.StatusCode)
	}

	// var loginResponse LoginResponse
	// err = json.Unmarshal(bodyBytes, &loginResponse)
	// if err != nil {
	// 	fmt.Println("Error unmarshalling response:", err)
	// 	return err
	// }
	// loginResponse := string(bodyBytes)

	// fmt.Printf("Response: %+v\n", loginResponse)

	// fmt.Println("Response status code:", resp.StatusCode)
	return nil
}

func (c *Client) Logout() error {
	fmt.Println("Logging out...")
	client := c.newUnsecureHTTPClient()

	body := []byte(fmt.Sprintf(`action=disconnect&login=%s&password_digest=%s`, url.QueryEscape(c.LoginUsername), url.QueryEscape(c.passwordDigest)))

	r, err := http.NewRequest("POST", c.LoginURL, bytes.NewBuffer(body))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading body:", err)
			return err
		}

		fmt.Println("[logout] Error response status code:", resp.StatusCode)
		fmt.Println("[logout] Response body:", string(bodyBytes))
		return fmt.Errorf("[logout] Error response status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) StartTicking() error {
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(c.PingIntervalSeconds))
		for range ticker.C {
			c.Ping()
		}
	}()
	return nil
}
