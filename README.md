# `sanitags`

`sanitags` is a flexible and customizable Go package that enables the sanitization of struct fields based on custom struct tags. It is particularly useful for cleaning up user input (e.g., removing or restricting HTML content) and preventing XSS attacks in web applications.

## Features
- **Tag-Based Sanitization**: Define sanitization behavior directly in struct tags.
- **Customizable Sanitization Functions**: Configure your own sanitization strategies or use third-party libraries (e.g., [Bluemonday](https://github.com/microcosm-cc/bluemonday)).
- **Support for Nested Structs**: Automatically applies sanitization recursively on nested or embedded structs.
- **Reflection-Based**: No need to change business logic; just apply tags and configure the sanitization methods.

## Installation

```bash
go get github.com/ullauri/sanitags
```

## How it works
The `sanitags` package sanitizes struct fields based on the `sanitize` tag. You can configure which functions will be used for sanitization by calling `Setup` and passing in a custom `Config` struct that defines your sanitization functions.

The struct fields can use one of the following tags:
- `sanitize:"stripall"`: Strips all HTML tags from the field.
- `sanitize:"safeugc"`: Cleans the field but allows user-generated content (UGC) that is considered safe.

## Example: Using `bluemonday` for sanitization
Here’s an example of how you can use sanitags with the popular [bluemonday](https://github.com/microcosm-cc/bluemonday) HTML sanitizer:
```go
package main

import (
    "fmt"
    "github.com/microcosm-cc/bluemonday"
    "github.com/ullauri/sanitags"
)

func main() {
    // Define sanitization configuration using bluemonday
    config := sanitags.Config{
        StripAllFunc: func(s string) string {
            return bluemonday.StrictPolicy().Sanitize(s)
        },
        UGCFunc: func(s string) string {
            return bluemonday.UGCPolicy().Sanitize(s)
        },
    }

    // Set up sanitags with the configuration
    sanitags.Setup(config)

    // Define a struct with sanitize tags
    type Address struct {
        City    string `sanitize:"stripall"`
        Country string `sanitize:"safeugc"`
    }

    type User struct {
        Name    string  `sanitize:"stripall"`
        Address Address
    }

    input := User{
        Name: "<h1>John Doe</h1>",
        Address: Address{
            City:    "<script>alert('xss')</script>",
            Country: "<b>Safe Content</b>",
        },
    }

    // Sanitize the struct
    err := sanitags.SanitizeStruct(&input)
    if err != nil {
        fmt.Println("Error during sanitization:", err)
        return
    }

    // Output the sanitized struct
    fmt.Printf("Sanitized struct: %+v\n", input)
}
```
Example Output:
```
Sanitized struct: {Name:John Doe Address:{City: Country:<b>Safe Content</b>}}
```
In this example:
- Fields tagged with `sanitize:"stripall"` are fully stripped of HTML content.
- Fields tagged with `sanitize:"safeugc"` allow safe HTML, like `<b>` tags.
