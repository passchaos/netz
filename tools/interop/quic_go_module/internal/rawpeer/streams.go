package rawpeer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"
)

const operationTimeout = 20 * time.Second

func Echo(ctx context.Context, connection *quic.Conn, id quic.StreamID, payload []byte) error {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != id {
		return fmt.Errorf("stream ID = %d, want %d", stream.StreamID(), id)
	}
	if err := stream.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		return err
	}
	if _, err := stream.Write(payload); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	echo, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	if string(echo) != string(payload) {
		return fmt.Errorf("stream %d echo %q, want %q", id, echo, payload)
	}
	return nil
}

func ExpectRemoteApplicationClose(ctx context.Context, connection *quic.Conn, code quic.ApplicationErrorCode, reason string) error {
	select {
	case <-connection.Context().Done():
		var applicationError *quic.ApplicationError
		cause := context.Cause(connection.Context())
		if !errors.As(cause, &applicationError) || !applicationError.Remote ||
			applicationError.ErrorCode != code || applicationError.ErrorMessage != reason {
			return fmt.Errorf("unexpected peer close: %w", cause)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for peer close: %w", context.Cause(ctx))
	}
}
