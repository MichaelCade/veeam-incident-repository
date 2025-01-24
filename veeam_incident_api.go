package main

import (
        "bytes"
        "crypto/tls"
        "encoding/json"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "time"

        "golang.org/x/term"
)

// Securely read input
func readSecureInput(prompt string) string {
        fmt.Print(prompt)
        bytePassword, err := term.ReadPassword(0)
        if err != nil {
                log.Fatalf("Failed to read input: %v", err)
        }
        fmt.Println() // Ensure a newline after input
        return string(bytePassword)
}

func main() {
        // Define flags
        insecure := flag.Bool("insecure", false, "Allow insecure HTTPS connections (skip certificate verification)")
        flag.Parse()

        // Environment variables or user input
        url := os.Getenv("VEEAM_API_URL")
        if url == "" {
                url = "https://192.168.169.185:9419/api/oauth2/token"
        }

        username := os.Getenv("VEEAM_API_USERNAME")
        if username == "" {
                fmt.Print("Enter username: ")
                fmt.Scanln(&username)
        }

        password := os.Getenv("VEEAM_API_PASSWORD")
        if password == "" {
                password = readSecureInput("Enter password: ")
        }

        // Configure HTTP client
        client := &http.Client{}
        if *insecure {
                // Disable TLS certificate verification
                tr := &http.Transport{
                        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                }
                client = &http.Client{Transport: tr}
        }

        // Obtain access token
        body := map[string]string{
                "grant_type": "password",
                "username":   username,
                "password":   password,
        }

        bodyJSON, err := json.Marshal(body)
        if err != nil {
                log.Fatalf("Failed to marshal JSON: %v", err)
        }

        req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
        if err != nil {
                log.Fatalf("Failed to create request: %v", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("x-api-version", "1.1-rev1")

        resp, err := client.Do(req)
        if err != nil {
                log.Fatalf("Failed to send request: %v", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                log.Fatalf("Failed to obtain token. HTTP Status: %s", resp.Status)
        }

        respBody, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                log.Fatalf("Failed to read response: %v", err)
        }

        var tokenResponse map[string]interface{}
        err = json.Unmarshal(respBody, &tokenResponse)
        if err != nil {
                log.Fatalf("Failed to parse JSON: %v", err)
        }

        token, ok := tokenResponse["access_token"].(string)
        if !ok || token == "" {
                log.Fatalf("Failed to obtain access token. Response: %s", string(respBody))
        }

        // Prepare event data
        detectionTime := time.Now().UTC().Format(time.RFC3339Nano)
        event := map[string]interface{}{
                "detectionTimeUtc": detectionTime,
                "machine": map[string]string{
                        "fqdn": "DevOps-MGMT01",
                        "uuid": "423738ed-997d-80d4-328f-f4fd78c887a4",
                },
                "details":  "Event-Driven Backup Demo",
                "severity": "Infected",
                "engine":   "Event-Driven",
        }

        eventBodyJSON, err := json.Marshal(event)
        if err != nil {
                log.Fatalf("Failed to marshal event JSON: %v", err)
        }

        eventURL := "https://192.168.169.185:9419/api/v1/malwareDetection/events"
        req, err = http.NewRequest("POST", eventURL, bytes.NewBuffer(eventBodyJSON))
        if err != nil {
                log.Fatalf("Failed to create event request: %v", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("x-api-version", "1.1-rev1")
        req.Header.Set("Authorization", "Bearer "+token)

        resp, err = client.Do(req)
        if err != nil {
                log.Fatalf("Failed to send event request: %v", err)
        }
        defer resp.Body.Close()

        eventRespBody, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                log.Fatalf("Failed to read event response: %v", err)
        }

        if resp.StatusCode != http.StatusOK {
                log.Fatalf("Failed to trigger event. HTTP Status: %s, Response: %s", resp.Status, string(eventRespBody))
        }

        fmt.Println("Event triggered successfully:")
        fmt.Println(string(eventRespBody))
}
