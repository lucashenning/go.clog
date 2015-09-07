package main

import (
	"fmt"
	"time"
	//"io"
	"io/ioutil"
	"crypto/aes"
    "crypto/cipher"
	"crypto/rsa"
    cryptorand "crypto/rand"
	mathrand "math/rand"
	"net/http"
    "crypto/tls"
	"encoding/json"
	"github.com/ActiveState/tail"
	"os"
	"log"
	"bytes"
	"encoding/base64"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"strings"
)

type Configuration struct {
	KeyServer string
	LogServer string
	Certificate string
	Logpath []string
}

type PubKeyDTO struct {
	PubKey string
	Id string
}

type EventDTO struct {
	Id string
	Iv string
	Ciphertext string
	EncryptedSessionKey string
}

func main() {
	fmt.Println("gocLog started at", time.Now())
	configuration := readConfig()
	fmt.Println("Config Url:", configuration.KeyServer)
	fmt.Println("Config Certificate:", configuration.Certificate)

	var wg sync.WaitGroup
	for _, logPath := range configuration.Logpath {
		wg.Add(1)
		go watchFile(logPath, configuration.KeyServer, configuration.LogServer, &wg) // Startet die Beobachtung mehrerer Logfiles parallel.
	}
	wg.Wait()
}

func watchFile(path string, keyServerUrl string, logServerUrl string, wg *sync.WaitGroup) {
	fmt.Println("Started Watching Process for File: ", path)
	t, err := tail.TailFile(path, tail.Config{Follow: true})
	if err != nil {
		log.Fatal(err)
	}
	for line := range t.Lines {
		fmt.Println(line.Text)
		response := httpsRequest(keyServerUrl) // Public Key von Schluessel Server holen
		var pubKeyDto PubKeyDTO
		err := json.Unmarshal([]byte(response), &pubKeyDto)
		if err != nil {
			log.Fatal("Unmarshal failed", err)
		}
		fmt.Println("Id:", pubKeyDto.Id)
		fmt.Println("Public Key:", pubKeyDto.PubKey)
		ciphertext, iv, encrypted_session_key, err := encrypt(line.Text, pubKeyDto.PubKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("IV:", encodeBase64(iv))
		fmt.Println("encrypted_session_key:", encodeBase64(encrypted_session_key))
		fmt.Println("Ciphertext:", encodeBase64(ciphertext))
		eventDTO := EventDTO{pubKeyDto.Id, encodeBase64(iv), encodeBase64(ciphertext), encodeBase64(encrypted_session_key)}
		sendEventToLogServer(logServerUrl, eventDTO)
	}
	wg.Done()
}

func encrypt(plaintext, encodedPubKey string) ([]byte, []byte, []byte, error) {
	// AES Encryption
	aesSessionKey := RandStringBytes(32) // 32 Bytes = AES-256
    aesCipher, err := aes.NewCipher([]byte(aesSessionKey))
	iv := []byte(RandStringBytes(aesCipher.BlockSize()))
    if err != nil {
        return nil, nil, nil, err
    }
	paddedPlainText := PKCS5Padding([]byte(plaintext), aesCipher.BlockSize())
    ciphertext := make([]byte, len(paddedPlainText))
    //if _, err := io.ReadFull(cryptorand.Reader, iv); err != nil {
    //    return nil, nil, nil, err
    //}
	//[aesCipher.BlockSize():]
    cbc := cipher.NewCBCEncrypter(aesCipher, iv) // Cipher Block Chaining
    cbc.CryptBlocks(ciphertext, paddedPlainText)

	// RSA Encryption
	encodedPubKey = fmt.Sprint("-----BEGIN RSA PUBLIC KEY-----\n",encodedPubKey,"\n-----END RSA PUBLIC KEY-----")
	rsaBlock, _ := pem.Decode([]byte(encodedPubKey))
	pubKey, err := x509.ParsePKIXPublicKey(rsaBlock.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	rsaPubKey := pubKey.(*rsa.PublicKey)
	encrypted_session_key, err := rsa.EncryptPKCS1v15(cryptorand.Reader, rsaPubKey, []byte(aesSessionKey))
	if err != nil {
		log.Fatal(err)
	}
    return ciphertext, iv, encrypted_session_key, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func encodeBase64(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func decodeBase64(src string) []byte {
	result, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	return result
}

func readConfig() Configuration {
	file, _ := os.Open("config.cfg")
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration
}

func httpsRequest(url string) string {
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    response, err := client.Get(url)
    if err != nil {
        fmt.Println(err)
    }
	body, err := ioutil.ReadAll(response.Body)
	return string(body)
}

func sendEventToLogServer(logServerUrl string, eventDTO EventDTO) {
	jsonStr, err := json.Marshal(eventDTO)
	jsonStr = []byte(renameFields(string(jsonStr)))
	jsonBytes := []byte(jsonStr)
	req, err := http.NewRequest("POST", logServerUrl, bytes.NewBuffer(jsonBytes))
	req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func renameFields(jsonStr string) string {
	jsonStr = strings.Replace(jsonStr,"Id","_id", -1)
	jsonStr = strings.Replace(jsonStr,"Iv","iv", -1)
	jsonStr = strings.Replace(jsonStr,"Ciphertext","ciphertext", -1)
	jsonStr = strings.Replace(jsonStr,"EncryptedSessionKey","encrypted_session_key", -1)
	return jsonStr
}

func RandStringBytes(n int) string {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[mathrand.Intn(len(letterBytes))]
    }
    return string(b)
}


