package raknet

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestDial_ConnectToServer tests that we can successfully dial a RakNet server
// and receive OpenConnectionReply1 and OpenConnectionReply2 packets during the
// connection sequence.
func TestDial_ConnectToServer(t *testing.T) {
	// Connect to a remote RakNet server
	serverAddr := "play.enchanted.gg:19132"

	// Create a dialer with a logger
	dialer := Dialer{
		ErrorLog: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Dial to the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Logf("Attempting to connect to %v", serverAddr)
	conn, err := dialer.DialContext(ctx, serverAddr)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	t.Logf("Successfully connected to server at %v (resolved to %v)", serverAddr, conn.RemoteAddr())

	// The fact that DialContext succeeded means we successfully:
	// 1. Sent OpenConnectionRequest1 and received OpenConnectionReply1
	// 2. Sent OpenConnectionRequest2 and received OpenConnectionReply2
	// 3. Sent ConnectionRequest and received ConnectionRequestAccepted
	t.Log("Connection sequence completed successfully - received OpenConnectionReply1 and OpenConnectionReply2")
}
