package main

import (
	"crypto/rand"
	mathrand "math/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	validHours          = flag.Int("hours", 4, "hours the certificate is valid for")
	caKeyPath           = flag.String("cakeypath", "/etc/ssh/ssh_ca.key", "path to the SSH CA private key")
	caKeyPasspharsePath = flag.String("cakeypasspath", "", "path to the SSH CA encrypted private key's passphrase")
)

func signUserCert(userPrincipal string, validHours int, pubKey ssh.PublicKey, caPublicKey ssh.PublicKey, signer ssh.Signer) (*ssh.Certificate, error) {
	exts := map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
	cert := &ssh.Certificate{
		ValidPrincipals: []string{userPrincipal},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Unix() + int64(validHours)*3600),
		Key:             pubKey,
		Serial:          mathrand.Uint64(),
		KeyId:					 fmt.Sprintf("ssh cert for %s", userPrincipal),
		CertType:        ssh.UserCert,
		SignatureKey:    caPublicKey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      exts,
		},
	}
	err := cert.SignCert(rand.Reader, signer)
	return cert, err
}

func addCertToAgent(key *ed25519.PrivateKey, cert *ssh.Certificate, validHours int) error {
	fmt.Printf("\n")
	addkey := &agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		LifetimeSecs: uint32(validHours * 3600),
	}
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		userSshAgent := agent.NewClient(sshAgent)
		fmt.Printf("adding certificate to ssh-agent\n")
		if err := (userSshAgent).Add(*addkey); err == nil {
			fmt.Errorf("added certificate to ssh-agent, please run ssh-add -L to verify\n")
			return nil
		} else {
			fmt.Errorf("Failed to add certificate to ssh-agent: %s\n", err)
			return err
		}
	} else {
		return err
	}
}

func main() {
	flag.Parse()
	var caKey ssh.Signer
	// generate client ssh key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	sshPubKey, err := ssh.NewPublicKey(privKey.Public())
	fmt.Printf("Generated ed25519 key pairs with the public key of:\n[%s]", ssh.MarshalAuthorizedKey(sshPubKey))
	if err != nil {
		fmt.Errorf("failed to create host key pair: %s\n", err)
		os.Exit(1)
	}
	// get current username to be used as certificate principal
	currentUser, err := user.Current()
	if err != nil {
		fmt.Errorf("failed to get current user: %s\n", err)
		os.Exit(1)
	}
	userPrincipal := currentUser.Username
	fmt.Printf("Current username [%s] will be used as certificate principal\n", userPrincipal)
	// read the CA private key file
	dat, err := ioutil.ReadFile(*caKeyPath)
	if err != nil {
		fmt.Errorf("failed to read ca key: %s\n", err)
		os.Exit(1)
	}

	if *caKeyPasspharsePath == "" {
		caKey, err = ssh.ParsePrivateKey(dat)
		if err != nil {
			fmt.Errorf("failed to parse ca key: %s\n", err)
			os.Exit(1)
		}
	} else {
		passphrasedat, err := ioutil.ReadFile(*caKeyPasspharsePath)
		if err != nil {
			fmt.Errorf("failed to read ca key passphrase file: %s\n", err)
			os.Exit(1)
		}
		caKey, err = ssh.ParsePrivateKeyWithPassphrase(dat, passphrasedat)
		if err != nil {
			fmt.Errorf("failed to parse encrypted ca key: %s\n", err)
			os.Exit(1)
		}
	}

	// get the CA public key from the private key
	caPublicKey := caKey.PublicKey()
	// create a signer from the CA private key
	cert, err := signUserCert(userPrincipal, *validHours, sshPubKey, caPublicKey, caKey)
	if err != nil {
		fmt.Errorf("failed to sign certificate: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signed certificate successfully by CA with the fingerprint [%s]", ssh.FingerprintSHA256(caPublicKey))
	if err := addCertToAgent(&privKey, cert, *validHours); err != nil {
		fmt.Errorf("failed to add ssh certificate to ssh agent: %s\n", err)
		os.Exit(1)
	}
}
