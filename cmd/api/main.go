package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/mAmineChniti/Gordian/internal/server"
)

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "localhost"
}

func main() {
	server := server.NewServer()
	LocalIP := getLocalIP()
	log.Printf("Server is running on http://%s%s", LocalIP, server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
}
