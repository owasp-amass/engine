package main

import (
	"fmt"

	"github.com/owasp-amass/config/config"
)

func main() {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err)
	}

}
