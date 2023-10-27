# Event type

The `Event` type is used to represent an Amass Engine's activity. The following
example demonstrates how to use the `Event` type:

```go
package main

import (
    "fmt"

    "github.com/owasp-amass/amass-engine/types"
)

type DNSAsset struct {
    Name    string
    Domain  string
    Address string
}

func main() {
    event := types.Event{
        Name:  "My first Event",
        Type:  types.EventTypeAsset,
        Data:  DNSAsset{
            Name:    "example.com",
            Domain:  "example.com",
            Address: "",
        },
    }

    // ...

}
```
