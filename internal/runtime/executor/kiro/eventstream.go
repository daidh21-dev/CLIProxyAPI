// Package kiro provides AWS EventStream decoding and execution logic for Kiro AI.
package kiro

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

var (
	ErrInvalidPrelude     = errors.New("eventstream: invalid prelude CRC32 checksum")
	ErrInvalidMessageCRC  = errors.New("eventstream: invalid message CRC32 checksum")
	ErrMessageTooShort    = errors.New("eventstream: message length is less than minimum 16 bytes")
	ErrUnexpectedEOF      = errors.New("eventstream: unexpected EOF while reading frame")
)

// EventStreamFrame represents a decoded AWS EventStream binary message.
type EventStreamFrame struct {
	Headers map[string]string
	Payload []byte
}

// EventType returns the :event-type header value if present.
func (f *EventStreamFrame) EventType() string {
	if f.Headers == nil {
		return ""
	}
	return f.Headers[":event-type"]
}

// MessageType returns the :message-type header value if present.
func (f *EventStreamFrame) MessageType() string {
	if f.Headers == nil {
		return ""
	}
	return f.Headers[":message-type"]
}

// ExceptionType returns the :exception-type header value if present.
func (f *EventStreamFrame) ExceptionType() string {
	if f.Headers == nil {
		return ""
	}
	return f.Headers[":exception-type"]
}

// ReadEventStreamFrame attempts to read and decode one EventStream frame from reader.
func ReadEventStreamFrame(r io.Reader) (*EventStreamFrame, error) {
	// Read 8-byte prelude: TotalLength (4), HeadersLength (4)
	var prelude [8]byte
	if _, err := io.ReadFull(r, prelude[:]); err != nil {
		return nil, err
	}

	totalLen := binary.BigEndian.Uint32(prelude[0:4])
	headersLen := binary.BigEndian.Uint32(prelude[4:8])

	if totalLen < 16 {
		return nil, ErrMessageTooShort
	}

	// Read Prelude CRC (4 bytes)
	var preludeCRCBytes [4]byte
	if _, err := io.ReadFull(r, preludeCRCBytes[:]); err != nil {
		return nil, ErrUnexpectedEOF
	}
	preludeCRC := binary.BigEndian.Uint32(preludeCRCBytes[:])

	// Validate Prelude CRC32 (IEEE)
	expectedPreludeCRC := crc32.ChecksumIEEE(prelude[:])
	if preludeCRC != expectedPreludeCRC {
		return nil, ErrInvalidPrelude
	}

	// Read remainder of message: headersLen + payloadLen + 4 bytes Message CRC
	remainderLen := totalLen - 12 // 8 (prelude) + 4 (preludeCRC)
	remainder := make([]byte, remainderLen)
	if _, err := io.ReadFull(r, remainder); err != nil {
		return nil, ErrUnexpectedEOF
	}

	// Message CRC is last 4 bytes of remainder
	messageCRC := binary.BigEndian.Uint32(remainder[remainderLen-4:])

	// Validate Message CRC32
	// Message CRC covers total message minus last 4 bytes (prelude + preludeCRC + remainder excluding last 4 bytes)
	fullData := append(append(prelude[:], preludeCRCBytes[:]...), remainder[:remainderLen-4]...)
	expectedMessageCRC := crc32.ChecksumIEEE(fullData)
	if messageCRC != expectedMessageCRC {
		return nil, ErrInvalidMessageCRC
	}

	// Extract Headers and Payload
	headersBytes := remainder[:headersLen]
	payloadBytes := remainder[headersLen : remainderLen-4]

	headers := parseEventStreamHeaders(headersBytes)

	return &EventStreamFrame{
		Headers: headers,
		Payload: payloadBytes,
	}, nil
}

// parseEventStreamHeaders parses the AWS EventStream header section into a key-value map.
func parseEventStreamHeaders(b []byte) map[string]string {
	headers := make(map[string]string)
	buf := bytes.NewReader(b)

	for buf.Len() > 0 {
		nameLenByte, err := buf.ReadByte()
		if err != nil {
			break
		}
		nameLen := int(nameLenByte)
		if buf.Len() < nameLen {
			break
		}

		nameBytes := make([]byte, nameLen)
		if _, err := buf.Read(nameBytes); err != nil {
			break
		}
		headerName := string(nameBytes)

		valueTypeByte, err := buf.ReadByte()
		if err != nil {
			break
		}
		valueType := int(valueTypeByte)

		// Type 7 = String (2 bytes length + string value)
		switch valueType {
		case 7: // String
			var strLen uint16
			if err := binary.Read(buf, binary.BigEndian, &strLen); err != nil {
				break
			}
			strBytes := make([]byte, strLen)
			if _, err := buf.Read(strBytes); err != nil {
				break
			}
			headers[headerName] = string(strBytes)
		case 0, 1: // True, False
			headers[headerName] = fmt.Sprintf("%t", valueType == 0)
		case 2: // Byte
			v, _ := buf.ReadByte()
			headers[headerName] = fmt.Sprintf("%d", v)
		case 3: // Short
			var v int16
			_ = binary.Read(buf, binary.BigEndian, &v)
			headers[headerName] = fmt.Sprintf("%d", v)
		case 4: // Integer
			var v int32
			_ = binary.Read(buf, binary.BigEndian, &v)
			headers[headerName] = fmt.Sprintf("%d", v)
		case 5, 8: // Long, Timestamp
			var v int64
			_ = binary.Read(buf, binary.BigEndian, &v)
			headers[headerName] = fmt.Sprintf("%d", v)
		case 6: // Byte Array
			var arrLen uint16
			_ = binary.Read(buf, binary.BigEndian, &arrLen)
			arr := make([]byte, arrLen)
			_, _ = buf.Read(arr)
			headers[headerName] = string(arr)
		case 9: // UUID (16 bytes)
			uuidBytes := make([]byte, 16)
			_, _ = buf.Read(uuidBytes)
			headers[headerName] = fmt.Sprintf("%x", uuidBytes)
		default:
			// Unknown type, stop parsing headers
			return headers
		}
	}

	return headers
}

// AssistantResponseEvent structure parsed from JSON payload of assistantResponseEvent
type AssistantResponseEvent struct {
	Content          string `json:"content,omitempty"`
	ReasoningContent string `json:"reasoningContent,omitempty"`
}

// ParseAssistantEvent attempts to unmarshal payload as AssistantResponseEvent or raw event JSON.
func (f *EventStreamFrame) ParseAssistantEvent() (content string, reasoning string, err error) {
	if excType := f.ExceptionType(); excType != "" {
		return "", "", fmt.Errorf("Kiro EventStream Exception [%s]: %s", excType, string(f.Payload))
	}
	if f.MessageType() == "exception" {
		return "", "", fmt.Errorf("Kiro EventStream Exception: %s", string(f.Payload))
	}

	if len(f.Payload) == 0 {
		return "", "", nil
	}

	var raw map[string]any
	if err := json.Unmarshal(f.Payload, &raw); err != nil {
		return "", "", err
	}

	// Check if raw payload contains an error/exception field
	if errMsg, ok := raw["message"].(string); ok && (f.EventType() == "exception" || strings.Contains(strings.ToLower(string(f.Payload)), "exception")) {
		return "", "", fmt.Errorf("Kiro EventStream Error: %s", errMsg)
	}

	// Extract content
	if c, ok := raw["content"].(string); ok {
		content = c
	} else if c, ok := raw["code"].(string); ok {
		content = c
	}

	// Extract reasoning
	if r, ok := raw["reasoningContent"].(string); ok {
		reasoning = r
	} else if r, ok := raw["reasoning"].(string); ok {
		reasoning = r
	}

	return content, reasoning, nil
}
