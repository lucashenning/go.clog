package main

import (
	"fmt"
	"time"
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
	"flag"
)

var configFlag = flag.String("config", "", "-config ./config.cfg")
var debugFlag  = flag.Bool("debug", false, "use -debug to see debug messages")

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
	Id 					string 	`json:"_id"`
	Iv 					string	`json:"iv"`
	Ciphertext 			string	`json:"ciphertext"`
	EncryptedSessionKey string	`json:"encrypted_session_key"`
}

func main() {
	flag.Parse()
	if *configFlag == "" {
		log.Fatal("No Config File specified. Please provide one using -config ./config.cfg")
	}
	fmt.Println("config: ", *configFlag)
	fmt.Println("gocLog started at", time.Now())
	debugMsg("DEBUG MODE IS ON!")
	configuration := readConfig(*configFlag)
	fmt.Println("Key-Server:", configuration.KeyServer)
	fmt.Println("Log-Server:", configuration.LogServer)
	fmt.Println("Certificate:", configuration.Certificate)

	var wg sync.WaitGroup
	for _, logPath := range configuration.Logpath {
		wg.Add(1)
		go watchFile(logPath, configuration.KeyServer, configuration.LogServer, &wg) // Startet die Beobachtung mehrerer Logfiles parallel.
	}
	wg.Wait()
}

func watchFile(path string, keyServerUrl string, logServerUrl string, wg *sync.WaitGroup) {
	fmt.Println("Watching file: ", path)
	t, err := tail.TailFile(path, tail.Config{Follow: true})
	if err != nil {
		log.Fatal(err)
	}
	for line := range t.Lines {
		response := httpsRequest(keyServerUrl) // Public Key von Schluessel Server holen
		var pubKeyDto PubKeyDTO
		err := json.Unmarshal([]byte(response), &pubKeyDto)
		if err != nil {
			log.Fatal("Unmarshal failed", err)
		}
		debugMsg(fmt.Sprint("Id:", pubKeyDto.Id))
		debugMsg(fmt.Sprint("Public Key:", pubKeyDto.PubKey))
		ciphertext, iv, encrypted_session_key, err := encrypt(line.Text, pubKeyDto.PubKey)
		if err != nil {
			log.Fatal(err)
		}
		debugMsg(fmt.Sprint("IV:", encodeBase64(iv)))
		debugMsg(fmt.Sprint("encrypted_session_key:", encodeBase64(encrypted_session_key)))
		debugMsg(fmt.Sprint("Ciphertext:", encodeBase64(ciphertext)))
		eventDTO := EventDTO{pubKeyDto.Id, encodeBase64(iv), encodeBase64(ciphertext), encodeBase64(encrypted_session_key)}
		sendEventToLogServer(logServerUrl, eventDTO)
		fmt.Println("Successfully sent log line to Log-Server. ID: ", pubKeyDto.Id)
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
    cbc := cipher.NewCBCEncrypter(aesCipher, iv) // Cipher Block Chaining
    cbc.CryptBlocks(ciphertext, paddedPlainText)

	// RSA Encryption
	encodedPubKey = fmt.Sprint("-----BEGIN RSA PUBLIC KEY-----\n",encodedPubKey,"\n-----END RSA PUBLIC KEY-----")
	rsaBlock, _ := pem.Decode([]byte(encodedPubKey))
	pubKey, err := x509.ParsePKIXPublicKey(rsaBlock.Bytes)
	if err != nil {
		log.Fatal(err)
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

func debugMsg (msg string) {
	if *debugFlag == true {
		fmt.Println(msg)
	}
}

func readConfig(path string) Configuration {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err = decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("Could not json decode config file", path)
		log.Fatal(err)
	}
	return configuration
}

func httpsRequest(url string) string {
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    response, err := client.Get(url)
	for err != nil {
		fmt.Println("Error. Keine Verbindung zum Key-Server ("+url+"). Neuer Versuch in 10 Sek.")
		time.Sleep(10 * time.Second)
		response, err = client.Get(url)
		if err == nil {
			fmt.Println("Verbindung zu Key-Server wieder hergestellt!")
		}
	}
	body, err := ioutil.ReadAll(response.Body)
	return string(body)
}

func sendEventToLogServer(logServerUrl string, eventDTO EventDTO) {
	jsonStr, err := json.Marshal(eventDTO)
	jsonBytes := []byte(jsonStr)
	req, err := http.NewRequest("POST", logServerUrl, bytes.NewBuffer(jsonBytes))
	req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	for err != nil {
		fmt.Println("Error. Keine Verbindung zum Log-Server ("+logServerUrl+"). Neuer Versuch in 10 Sek.")
		time.Sleep(10 * time.Second)
		resp, err = client.Do(req)
		if err == nil {
			fmt.Println("Verbindung zu Log-Server wieder hergestellt!")
		}
	}
	defer resp.Body.Close()
}

func RandStringBytes(n int) string {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[mathrand.Intn(len(letterBytes))]
    }
    return string(b)
}


