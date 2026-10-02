package clientsdb

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

type ClientInfo struct {
	Comment string `json:"comment,omitempty"`
}

type Data struct {
	Clients map[string]ClientInfo `json:"clients"`
}

type DB struct {
	mu           sync.RWMutex
	path         string
	data         Data
	lastModified time.Time
}

func New(path string) (*DB, error) {
	db := &DB{
		path: path,
		data: Data{Clients: make(map[string]ClientInfo)},
	}

	if err := db.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return db, nil
}

func (db *DB) StartHotReload(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			db.loadIfModified()
		}
	}()
}

func (db *DB) IsAuthorized(clientID string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	_, ok := db.data.Clients[clientID]
	return ok
}

func (db *DB) Add(clientID, comment string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.data.Clients[clientID] = ClientInfo{Comment: comment}
	return db.save()
}

func (db *DB) Remove(clientID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.data.Clients, clientID)
	return db.save()
}

func (db *DB) List() map[string]ClientInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()

	res := make(map[string]ClientInfo)
	for k, v := range db.data.Clients {
		res[k] = v
	}
	return res
}

func (db *DB) load() error {
	stat, err := os.Stat(db.path)
	if err != nil {
		return err
	}

	b, err := os.ReadFile(db.path)
	if err != nil {
		return err
	}

	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("failed to parse %s: %w", db.path, err)
	}

	if d.Clients == nil {
		d.Clients = make(map[string]ClientInfo)
	}

	db.data = d
	db.lastModified = stat.ModTime()
	return nil
}

func (db *DB) loadIfModified() {
	stat, err := os.Stat(db.path)
	if err != nil {
		return
	}

	db.mu.RLock()
	modTime := db.lastModified
	db.mu.RUnlock()

	if stat.ModTime().After(modTime) {
		db.mu.Lock()
		_ = db.load()
		db.mu.Unlock()
	}
}

func (db *DB) save() error {
	b, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := db.path + ".tmp"
	err = os.WriteFile(tmpFile, b, 0o600) // 0o600: файл содержит Client ID токены авторизации
	if err == nil {
		err = os.Rename(tmpFile, db.path)
	}
	if err == nil {
		stat, _ := os.Stat(db.path)
		if stat != nil {
			db.lastModified = stat.ModTime()
		}
	}
	return err
}

// Тег режима едет хвостом той же записи: клиент до этого поля его не писал, а читатель
// брал ровно 1+len байт - лишний байт старый сервер молча пропускает.
const (
	ModeUnset byte = 0
	ModeUDP   byte = 1
	ModeTCP   byte = 2
)

// WriteClientID отправляет Client ID (1 байт длины + строка + 1 байт режима).
func WriteClientID(conn net.Conn, clientID string, mode byte) error {
	return WriteClientHello(conn, clientID, mode, 0)
}

// WriteClientStream sends the stable, positive stream number used by a relay.
func WriteClientStream(conn net.Conn, clientID string, mode byte, streamID int) error {
	if streamID <= 0 || int64(streamID) > math.MaxUint32 {
		return fmt.Errorf("invalid stream ID: %d", streamID)
	}
	return WriteClientHello(conn, clientID, mode, uint32(streamID))
}

// WriteClientHello sends an optional stable stream ID after the legacy ID/mode.
// Stream zero retains the legacy record. Upgrade the server first to support
// replacement and extended hellos with IDs longer than 251 bytes.
func WriteClientHello(conn net.Conn, clientID string, mode byte, streamID uint32) error {
	b := []byte(clientID)
	if len(b) > 255 {
		b = b[:255]
	}
	size := 1 + len(b) + 1
	if streamID != 0 {
		size += 4
	}
	buf := make([]byte, size)
	buf[0] = byte(len(b)) //nolint:gosec // len(b) усечён до ≤255 выше
	copy(buf[1:], b)
	buf[1+len(b)] = mode
	if streamID != 0 {
		binary.BigEndian.PutUint32(buf[2+len(b):], streamID)
	}
	n, err := conn.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return err
}

// ReadClientID читает Client ID из первой DTLS-записи. Режим ModeUnset - клиент старше
// тега, режим у него всегда udp.
func ReadClientID(conn net.Conn) (string, byte, error) {
	id, mode, _, err := ReadClientHello(conn)
	return id, mode, err
}

// ReadClientHello reads one DTLS application record, accepting legacy hellos.
// A legacy client has stream ID zero and cannot safely replace a specific stream.
func ReadClientHello(conn net.Conn) (string, byte, uint32, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 262)
	n, err := conn.Read(buf)
	if err != nil {
		return "", ModeUnset, 0, err
	}
	if n == 0 {
		return "", ModeUnset, 0, nil
	}
	l := int(buf[0])
	if n < 1+l {
		return "", ModeUnset, 0, io.ErrUnexpectedEOF
	}
	mode := ModeUnset
	if n > 1+l {
		mode = buf[1+l]
	}
	var streamID uint32
	switch n - (1 + l) {
	case 0, 1:
	case 5:
		streamID = binary.BigEndian.Uint32(buf[2+l : n])
	default:
		return "", ModeUnset, 0, fmt.Errorf("invalid client hello extension length: %d", n-(1+l))
	}
	return string(buf[1 : 1+l]), mode, streamID, nil
}
