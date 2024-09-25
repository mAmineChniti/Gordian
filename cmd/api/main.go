package main

import (
	"fmt"
	"log"

	"github.com/mAmineChniti/Gordian/internal/server"
)

func main() {

	server := server.NewServer()
	err := server.ListenAndServe()
	if err != nil {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
	log.Print(fmt.Sprintf("Server is running on port %s", server.Addr))
}
