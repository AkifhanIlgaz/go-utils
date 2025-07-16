package main

import "encoding/json"

func main() {

}

func printJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	println(string(b))
	println("---")
}
