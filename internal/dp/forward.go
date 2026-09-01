package dp

import (
	"context"
	"io"
	"log"
	"sync"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// directTCPIPPayload is the channel-open payload for client-initiated
// forwarding: "I want a connection to this address, tunnelled through you".
type directTCPIPPayload struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// tcpipForwardPayload is the global request asking the target to listen on the
// client's behalf.
type tcpipForwardPayload struct {
	BindHost string
	BindPort uint32
}

// forwardedTCPIPPayload is the channel the target opens back when something
// connects to a remote forward.
type forwardedTCPIPPayload struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// handleDirectTCPIP proxies a client-initiated tunnel.
//
// This is what `ssh -L` and `ssh -D` produce. It is a real privilege — it turns
// the proxy into a route to anything the target can reach — so it is gated and
// each tunnel is recorded individually rather than being folded into the
// session's byte counters.
func (c *connection) handleDirectTCPIP(ctx context.Context, newChannel ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}

	if err := c.authorizeChannel(ctx, &sshproxyv1.AuthorizeChannelRequest{
		ChannelType: sshproxyv1.ChannelType_CHANNEL_TYPE_DIRECT_TCPIP,
		DestHost:    payload.DestHost,
		DestPort:    int32(payload.DestPort),
	}); err != nil {
		log.Printf("dp: session %s: refusing forward to %s:%d: %v",
			c.sessionID, payload.DestHost, payload.DestPort, err)
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}

	upstreamChannel, upstreamRequests, err := c.upstream.OpenChannel("direct-tcpip", newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "target refused the forward: "+err.Error())
		return
	}
	go ssh.DiscardRequests(upstreamRequests)

	clientChannel, clientRequests, err := newChannel.Accept()
	if err != nil {
		_ = upstreamChannel.Close()
		return
	}
	go ssh.DiscardRequests(clientRequests)

	c.trackChannel(clientChannel)
	defer c.untrackChannel(clientChannel)

	log.Printf("dp: session %s: forwarding to %s:%d", c.sessionID, payload.DestHost, payload.DestPort)
	c.pipeTunnel(clientChannel, upstreamChannel)
}

// handleRemoteForwardRequest gates `ssh -R`, where the target starts listening.
func (c *connection) handleRemoteForwardRequest(ctx context.Context, req *ssh.Request) {
	if req.Type == "cancel-tcpip-forward" {
		// Withdrawing a listener grants nothing, so it is relayed unchecked.
		c.forwardGlobalRequest(req)
		return
	}

	var payload tcpipForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if err := c.authorizeChannel(ctx, &sshproxyv1.AuthorizeChannelRequest{
		ChannelType: sshproxyv1.ChannelType_CHANNEL_TYPE_FORWARDED_TCPIP,
		RequestType: sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_TCPIP_FORWARD,
		DestHost:    payload.BindHost,
		DestPort:    int32(payload.BindPort),
	}); err != nil {
		log.Printf("dp: session %s: refusing remote forward on %s:%d: %v",
			c.sessionID, payload.BindHost, payload.BindPort, err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	c.forwardGlobalRequest(req)
}

// serveUpstreamChannels handles channels the target opens back towards the
// client, which is how a remote forward delivers its connections.
//
// Without this, `ssh -R` would appear to succeed and then never deliver
// anything, because the target's inbound channel would have nowhere to go.
func (c *connection) serveUpstreamChannels(ctx context.Context) {
	kinds := map[string]sshproxyv1.ChannelType{
		"forwarded-tcpip":        sshproxyv1.ChannelType_CHANNEL_TYPE_FORWARDED_TCPIP,
		"x11":                    sshproxyv1.ChannelType_CHANNEL_TYPE_X11,
		"auth-agent@openssh.com": sshproxyv1.ChannelType_CHANNEL_TYPE_AGENT,
	}
	for name, kind := range kinds {
		channels := c.upstream.HandleChannelOpen(name)
		if channels == nil {
			continue
		}
		go func(name string, kind sshproxyv1.ChannelType, channels <-chan ssh.NewChannel) {
			for newChannel := range channels {
				if name == "forwarded-tcpip" {
					go c.handleForwardedTCPIP(ctx, newChannel)
					continue
				}
				go c.handleUpstreamOriginated(ctx, newChannel, kind)
			}
		}(name, kind, channels)
	}
}

func (c *connection) handleForwardedTCPIP(ctx context.Context, newChannel ssh.NewChannel) {
	var payload forwardedTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "malformed forwarded-tcpip request")
		return
	}
	if err := c.authorizeChannel(ctx, &sshproxyv1.AuthorizeChannelRequest{
		ChannelType: sshproxyv1.ChannelType_CHANNEL_TYPE_FORWARDED_TCPIP,
		DestHost:    payload.DestHost,
		DestPort:    int32(payload.DestPort),
	}); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	c.bridgeUpstreamChannel(newChannel, "forwarded-tcpip")
}

func (c *connection) handleUpstreamOriginated(ctx context.Context, newChannel ssh.NewChannel, kind sshproxyv1.ChannelType) {
	if err := c.authorizeChannel(ctx, &sshproxyv1.AuthorizeChannelRequest{
		ChannelType: kind,
	}); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	c.bridgeUpstreamChannel(newChannel, newChannel.ChannelType())
}

// bridgeUpstreamChannel opens the matching channel on the client side and joins
// the two.
func (c *connection) bridgeUpstreamChannel(newChannel ssh.NewChannel, channelType string) {
	clientChannel, clientRequests, err := c.client.OpenChannel(channelType, newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "client refused the channel")
		return
	}
	go ssh.DiscardRequests(clientRequests)

	upstreamChannel, upstreamRequests, err := newChannel.Accept()
	if err != nil {
		_ = clientChannel.Close()
		return
	}
	go ssh.DiscardRequests(upstreamRequests)

	c.trackChannel(clientChannel)
	defer c.untrackChannel(clientChannel)
	c.pipeTunnel(clientChannel, upstreamChannel)
}

// pipeTunnel joins two channels, counting the bytes and closing both when
// either direction finishes.
func (c *connection) pipeTunnel(clientChannel, upstreamChannel ssh.Channel) {
	defer func() {
		_ = clientChannel.Close()
		_ = upstreamChannel.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstreamChannel, clientChannel)
		c.bytesIn.Add(n)
		_ = upstreamChannel.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientChannel, upstreamChannel)
		c.bytesOut.Add(n)
		_ = clientChannel.CloseWrite()
	}()
	wg.Wait()
}
