package main

import (
	"encoding/json"
	"io"
	"net/http"
)

func parseJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func encodeJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	return string(data), err
}

func decodeJSON(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}
