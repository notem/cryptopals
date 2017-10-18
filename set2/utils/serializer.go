/*
dependencies: https://github.com/cevaris/ordered_map
 */
package utils

import (
	"regexp"
	"github.com/cevaris/ordered_map"
)

// de-serializes a string containing a list of k=v parameters
// this function consumes '&' and '=' characters which do not map
// using the regex parser
func DeserializeParameters(parameters string) (*ordered_map.OrderedMap) {

	dict := ordered_map.NewOrderedMap()
	matcher := regexp.MustCompile("(.+?)=(.+?)&|(.+?)=(.+?)$")

	// fill the dictionary with k=v pairs
	for {	// while true loop
		match := matcher.FindStringSubmatchIndex(parameters)

		if match[2] >= 0 {
			// if regex groups 1 and 2 are found
			key := Sanitize(parameters[match[2]:match[3]])
			value := Sanitize(parameters[match[4]:match[5]])
			dict.Set(key, value)	// add to dictionary

			// slice off the processed k=v pair
			parameters = parameters[match[1]:]
		} else {
			// else regex groups 3 and 4 have been found
			key := Sanitize(parameters[match[6]:match[7]])
			value := Sanitize(parameters[match[8]:])
			dict.Set(key, value)	// add to dictionary

			// processed last k=v pair, break the loop
			break
		}
	}
	return dict
}

// a mapping of keys and values to a string containing a list of k=v parameters
func SerializeParameter(dict *ordered_map.OrderedMap) (string) {

	parameters := ""
	count := 0
	iter := dict.IterFunc()
	for kv, ok := iter(); ok; kv, ok = iter() {
		// append k=v
		parameters += kv.Key.(string) + "=" + kv.Value.(string); count++

		// if not last dictionary element, append '&'
		if count < dict.Len() {
			parameters += "&"
		}
	}
	return parameters
}

// removes '&' and '=' characters from a serialized parameter string
func Sanitize(input string) (string){
	return regexp.MustCompile("[&=]").ReplaceAllString(input, "")
}
