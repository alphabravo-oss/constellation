// Test-owned HTTP endpoints and fresh-connection probe. Never used by the agent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type observation struct {
	Nonce  string    `json:"nonce"`
	Pod    string    `json:"pod"`
	Port   int       `json:"port"`
	Remote string    `json:"remote"`
	Local  string    `json:"local"`
	At     time.Time `json:"at"`
}

func main() {
	mode := flag.String("mode", "server", "server, idle, or probe")
	flag.Parse()
	var err error
	switch *mode {
	case "server":
		err = serve(os.Getenv("POD_NAME"))
	case "idle":
		for {
			time.Sleep(time.Hour)
		}
	case "probe":
		err = probeInput()
	default:
		err = errors.New("unknown fixture mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(pod string) error {
	if pod != "server-a" && pod != "server-b" {
		return errors.New("unexpected server identity")
	}
	var mu sync.Mutex
	outcomes := make(chan error, 2)
	for _, port := range []int{18080, 18081} {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := strings.TrimPrefix(r.URL.Path, "/probe/")
			if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/probe/") || !validNonce(nonce) {
				http.Error(w, "invalid probe", http.StatusBadRequest)
				return
			}
			row := observation{Nonce: nonce, Pod: pod, Port: port, Remote: r.RemoteAddr, Local: r.Host, At: time.Now().UTC()}
			mu.Lock()
			logErr := json.NewEncoder(os.Stdout).Encode(row)
			mu.Unlock()
			if logErr != nil {
				http.Error(w, "observation unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(row); err != nil {
				return
			}
		})
		server := &http.Server{Addr: net.JoinHostPort("0.0.0.0", strconv.Itoa(port)), Handler: handler, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}
		go func() { outcomes <- server.ListenAndServe() }()
	}
	return <-outcomes
}

func validNonce(nonce string) bool {
	if len(nonce) < 3 || len(nonce) > 100 {
		return false
	}
	for _, c := range nonce {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func probeInput() error {
	var request struct {
		Target     string `json:"target"`
		Port       int    `json:"port"`
		SourcePort int    `json:"source_port"`
		Nonce      string `json:"nonce"`
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	return probe(request.Target, request.Port, request.SourcePort, request.Nonce)
}

func probe(target string, port, source int, nonce string) error {
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil || ip.IsLoopback() || !ip.IsPrivate() || port < 18080 || port > 18081 || source < 40000 || source > 45000 || !validNonce(nonce) {
		return errors.New("invalid fixture probe scope")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	dialer := &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{Port: source}}
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(target, strconv.Itoa(port))+"/probe/"+nonce, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || len(body) > 4096 {
		return errors.New("fixture response rejected")
	}
	var row observation
	if err := json.Unmarshal(body, &row); err != nil {
		return err
	}
	_, remotePort, err := net.SplitHostPort(row.Remote)
	if err != nil || row.Nonce != nonce || row.Port != port || remotePort != strconv.Itoa(source) {
		return errors.New("fixture response identity mismatch")
	}
	_, err = os.Stdout.Write(body)
	return err
}
