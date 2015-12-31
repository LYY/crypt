package etcdv3

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/sedarasecurity/crypt/backend"

	"github.com/coreos/etcd/client"
)

type Client struct {
	client    client.Client
	keycli    client.KeysAPI
	waitIndex uint64
}

func newWithConfig(cfg client.Config) (*Client, error) {
	cli, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	go func(c client.Client) {
		for {
			err := c.AutoSync(context.Background(), 30*time.Second)
			if err == context.DeadlineExceeded || err == context.Canceled {
				break
			}
			if err != nil {
				log.Println(err)
			}
		}
	}(cli)

	kapi := client.NewKeysAPI(cli)

	return &Client{cli, kapi, 0}, nil
}

func NewTLS(machines []string, caPath, certPath, keyPath string) (*Client, error) {
	// If you are using a self-signed cert and need to load in the CA.
	rootPEM, err := ioutil.ReadFile(caPath)
	if err != nil || rootPEM == nil {
		return nil, fmt.Errorf("failed to read root certificate")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	// If the server requires client certificates..
	certFile := certPath
	keyFile := keyPath
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing X509 certificate/key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	var tlsTransport client.CancelableTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}

	cfg := client.Config{
		Endpoints: machines,
		Transport: tlsTransport,
	}

	return newWithConfig(cfg)
}

func New(machines []string) (*Client, error) {
	cfg := client.Config{
		Endpoints: machines,
		Transport: client.DefaultTransport,
	}

	return newWithConfig(cfg)
}

func (c *Client) Get(key string) ([]byte, error) {
	resp, err := c.keycli.Get(context.Background(), key, nil)
	if err != nil {
		return nil, err
	}
	return []byte(resp.Node.Value), nil
}

func addKVPairs(node *client.Node, list backend.KVPairs) backend.KVPairs {
	if node.Dir {
		for _, n := range node.Nodes {
			list = addKVPairs(n, list)
		}
		return list
	}
	return append(list, &backend.KVPair{Key: node.Key, Value: []byte(node.Value)})
}

func (c *Client) List(key string) (backend.KVPairs, error) {
	resp, err := c.keycli.Get(context.Background(), key, &client.GetOptions{Sort: false, Recursive: true})
	if err != nil {
		return nil, err
	}
	if !resp.Node.Dir {
		return nil, errors.New("key is not a directory")
	}
	list := addKVPairs(resp.Node, nil)
	return list, nil
}

func (c *Client) Set(key string, value []byte) error {
	_, err := c.keycli.Set(context.Background(), key, string(value), nil)
	return err
}

func (c *Client) Watch(key string) <-chan *backend.Response {
	respChan := make(chan *backend.Response, 0)
	go func() {
		watcher := c.keycli.Watcher(key, nil)
		for {
			resp, err := watcher.Next(context.Background())
			if err != nil {
				respChan <- &backend.Response{Value: nil, Error: err}
				time.Sleep(time.Second * 5)
				continue
			}
			// c.waitIndex = resp.Node.ModifiedIndex
			respChan <- &backend.Response{Value: []byte(resp.Node.Value), Error: nil}
		}
	}()
	return respChan
}
