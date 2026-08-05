package kiro

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func createTestEventStreamFrame(headers map[string]string, payload []byte) []byte {
	var headersBuf bytes.Buffer

	for k, v := range headers {
		headersBuf.WriteByte(byte(len(k)))
		headersBuf.WriteString(k)
		headersBuf.WriteByte(7) // String type
		binary.Write(&headersBuf, binary.BigEndian, uint16(len(v)))
		headersBuf.WriteString(v)
	}

	headersBytes := headersBuf.Bytes()
	headersLen := uint32(len(headersBytes))
	totalLen := uint32(16 + len(headersBytes) + len(payload))

	var prelude [8]byte
	binary.BigEndian.PutUint32(prelude[0:4], totalLen)
	binary.BigEndian.PutUint32(prelude[4:8], headersLen)
	preludeCRC := crc32.ChecksumIEEE(prelude[:])

	var fullData bytes.Buffer
	fullData.Write(prelude[:])
	binary.Write(&fullData, binary.BigEndian, preludeCRC)
	fullData.Write(headersBytes)
	fullData.Write(payload)

	msgCRC := crc32.ChecksumIEEE(fullData.Bytes())
	binary.Write(&fullData, binary.BigEndian, msgCRC)

	return fullData.Bytes()
}

func TestReadEventStreamFrame(t *testing.T) {
	headers := map[string]string{
		":event-type":   "assistantResponseEvent",
		":message-type": "event",
	}
	payload := []byte(`{"content":"Hello from Kiro!","reasoningContent":"Thinking..."}`)

	frameBytes := createTestEventStreamFrame(headers, payload)
	reader := bytes.NewReader(frameBytes)

	frame, err := ReadEventStreamFrame(reader)
	if err != nil {
		t.Fatalf("unexpected error decoding frame: %v", err)
	}

	if frame.EventType() != "assistantResponseEvent" {
		t.Errorf("expected event-type 'assistantResponseEvent', got '%s'", frame.EventType())
	}

	content, reasoning, err := frame.ParseAssistantEvent()
	if err != nil {
		t.Fatalf("failed to parse assistant event: %v", err)
	}

	if content != "Hello from Kiro!" {
		t.Errorf("expected content 'Hello from Kiro!', got '%s'", content)
	}

	if reasoning != "Thinking..." {
		t.Errorf("expected reasoning 'Thinking...', got '%s'", reasoning)
	}
}
