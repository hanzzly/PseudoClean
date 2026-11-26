package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ============================================================================
// 1. STRING & SLICE RUNTIME
// Target: stringtoslicebyte, slicebytetostring, growslice, concatstring2..N
// ============================================================================

//go:noinline
func idiomStringSlice(input string) string {
	// runtime.stringtoslicebyte
	b := []byte(input)

	// runtime.growslice (append)
	b = append(b, '!', '?', 0x41, 0x42)

	// runtime.slicebytetostring
	s1 := string(b)

	// runtime.concatstring2
	s2 := s1 + "_suffix"

	// runtime.concatstring5 (N > 4)
	s3 := input + ":" + s1 + ":" + s2

	return strings.TrimSpace(s3)
}

// ============================================================================
// 2. INPUT / CLI / FILE
// Target: os.Args, os.ReadFile, os.Open, bufio.Scanner, fmt.Scanln
// ============================================================================

//go:noinline
func idiomFileCLI(args []string) ([]byte, error) {
	if len(args) < 2 {
		return nil, errors.New("path file tidak diberikan")
	}

	// Multi-return (retval_*) + os.ReadFile
	data, err := os.ReadFile(args[1])
	if err != nil {
		return nil, err
	}

	// os.Open + defer Close
	f, err := os.Open(args[1])
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		data = append(data, scanner.Bytes()...)
	}

	var userInput string
	fmt.Scanln(&userInput)
	data = append(data, []byte(userInput)...)

	return data, nil
}

// ============================================================================
// 3. CONTROL FLOW & ERROR
// Target: panicIndex, panicBounds, gopanic, deferwrap, recover, retval_*
// ============================================================================

//go:noinline
func idiomControlFlow(buf []byte, idx int) (val byte, err error) {
	// defer closure (deferwrap) + recover
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("terjadi panic: %v", r)
		}
	}()

	// runtime.gopanic
	if idx < 0 {
		panic("indeks tidak boleh negatif")
	}

	// runtime.panicIndex
	val = buf[idx]

	// runtime.panicBounds (slice bounds check)
	sub := buf[1:idx]
	if len(sub) > 0 {
		val ^= sub[0]
	}

	return val, nil
}

// ============================================================================
// 4. DATA STRUCTURES (MAP, STRUCT, INTERFACE)
// Target: makemap, mapaccess1/2, mapassign, ITab, convT64, method receiver
// ============================================================================

type Processor interface {
	Process(data []byte) int
}

type XorProcessor struct {
	Key  byte
	Name string
}

//go:noinline
func (x *XorProcessor) Process(data []byte) int {
	sum := 0
	for _, b := range data {
		sum += int(b ^ x.Key)
	}
	return sum
}

//go:noinline
func idiomDataStructures(keys []string, vals []int) int {
	// runtime.makemap
	m := make(map[string]int)

	// runtime.mapassign
	for i, k := range keys {
		if i < len(vals) {
			m[k] = vals[i]
		}
	}

	// runtime.mapaccess1
	v1 := m[keys[0]]

	// runtime.mapaccess2 (comma-ok idiom)
	v2, ok := m["flag_key"]
	if !ok {
		v2 = 42
	}

	// Interface assignment (go:itab.*main.XorProcessor,main.Processor)
	var proc Processor = &XorProcessor{Key: 0x5A, Name: "custom_xor"}

	// runtime.convT64 (boxing primitive ke empty interface any)
	var boxed any = v1 + v2
	payload := []byte(fmt.Sprintf("%v", boxed))

	// Pemanggilan method via interface vtable
	return proc.Process(payload)
}

// ============================================================================
// 5. CONCURRENCY
// Target: newproc (goroutine), makechan, chansend1, chanrecv1, WaitGroup
// ============================================================================

//go:noinline
func idiomConcurrency(jobs []int) int {
	// runtime.makechan
	ch := make(chan int, len(jobs))
	var wg sync.WaitGroup

	for _, job := range jobs {
		// sync.(*WaitGroup).Add
		wg.Add(1)

		// runtime.newproc
		go func(n int) {
			defer wg.Done()
			// runtime.chansend1
			ch <- n * 3
		}(job)
	}

	// sync.(*WaitGroup).Wait
	wg.Wait()
	close(ch)

	total := 0
	// runtime.chanrecv1
	for res := range ch {
		total += res
	}
	return total
}

// ============================================================================
// 6. CRYPTO & ENCODING
// Target: strconv, sha256, md5, rc4, aes, cipher.BlockMode, binary, base64, hex
// ============================================================================

//go:noinline
func idiomCryptoEncoding(raw string) ([]byte, error) {
	// strconv.Atoi & strconv.Itoa
	num, err := strconv.Atoi(raw)
	if err != nil {
		num = 1337
	}
	numStr := strconv.Itoa(num)

	// crypto/sha256 & crypto/md5
	hash256 := sha256.Sum256([]byte(numStr))
	hashMD5 := md5.Sum(hash256[:])

	// crypto/rc4
	rc4Cipher, err := rc4.NewCipher(hashMD5[:])
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(hash256))
	rc4Cipher.XORKeyStream(buf, hash256[:])

	// crypto/aes + crypto/cipher (CBC mode)
	block, err := aes.NewCipher(hash256[:16])
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, hashMD5[:16])
	cbc.CryptBlocks(buf, buf)

	// encoding/binary
	val64 := binary.LittleEndian.Uint64(buf[:8])
	var binBuf bytes.Buffer
	_ = binary.Write(&binBuf, binary.BigEndian, val64)

	// encoding/base64 & encoding/hex
	b64 := base64.StdEncoding.EncodeToString(binBuf.Bytes())
	hx := hex.EncodeToString(buf[:8])

	return []byte(b64 + ":" + hx), nil
}

func main() {
	// Gunakan os.Args agar compiler tidak melakukan constant-folding saat compile
	seed := "12345"
	if len(os.Args) > 1 {
		seed = os.Args[1]
	}

	s := idiomStringSlice(seed)
	data, _ := idiomFileCLI(os.Args)
	if len(data) == 0 {
		data = []byte(s)
	}

	b, _ := idiomControlFlow(data, 2)
	score := idiomDataStructures([]string{seed, "flag_key"}, []int{int(b), 99})
	total := idiomConcurrency([]int{score, 10, 20})
	out, _ := idiomCryptoEncoding(strconv.Itoa(total))

	fmt.Println(string(out))
}
