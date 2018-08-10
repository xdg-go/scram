package scram_test

import "github.com/xdg/scram"

func Example() error {
	// Get Client with username, password and (optional) authorization ID.
	clientSHA1, err := scram.SHA1.NewClient("mulder", "trustno1", "")
	if err != nil {
		return err
	}

	// Prepare the authentication conversation. Use the empty string as the
	// initial server message argument to start the conversation.
	conv := clientSHA1.NewConversation()
	var serverMsg string

	// Get the first message, send it and read the response.
	firstMsg, err := conv.Step(serverMsg)
	if err != nil {
		return err
	}
	serverMsg = send_client_msg(firstMsg)

	// Get the second message, send it, and read the response.
	secondMsg, err := conv.Step(serverMsg)
	if err != nil {
		return err
	}
	serverMsg = send_client_msg(secondMsg)

	// Validate the server's final message.  We have no further message to
	// send so ignore that return value.
	_, err = conv.Step(serverMsg)
	if err != nil {
		return err
	}

	return nil
}

func send_client_msg(s string) string {
	// A real implementation would send this to a server and read a reply.
	return ""
}
