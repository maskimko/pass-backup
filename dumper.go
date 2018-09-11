package main

import (
	"fmt"
	"log"
	"os"
)

type dumper struct {
	Destination string
	Buffer      []byte
}

func getDumper(dest *string, bufferSize int16) *dumper {
	return &dumper{Destination: *dest, Buffer: make([]byte, 0, bufferSize)}
}

func (d *dumper) WriteString(s *string) int {
	var b []byte = []byte(*s)
	d.Buffer = append(d.Buffer, b...)
	return len(b)
}

func (d *dumper) Flush() (int, error) {
	if d.Destination == "-" || d.Destination == "" {
		log.Println("Storing to stdout")
		fmt.Print(string(d.Buffer))
		return len(d.Buffer), nil
	} else {
		log.Println("Storing to ", d.Destination)
		f, err := os.Create(d.Destination)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		n, err := f.Write(d.Buffer)
		if err != nil {
			return 0, err
		}
		f.Sync()
		return n, nil
	}
}
