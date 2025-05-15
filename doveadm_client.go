package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"log"
	"strings"
)

type DoveadmClient struct {
	api         *APIClient
	verbose     bool
	moreVerbose bool
}

/*

Doveadmin API command
list of elements [string, object, string]

[
    [
	"command",
	{
	    "param1": "value1",
	    "param2": "value2"
	},
	"tag1"
    ]
]

*/

func NewDoveadmClient() (*DoveadmClient, error) {

	url := viper.GetString("doveadm_url")
	headers := make(map[string]string)
	key := viper.GetString("doveadm_api_key")
	value := viper.GetString("doveadm_api_value")
	headers[key] = value
	headers["Content-Type"] = "application/json"
	api, err := NewAPIClient(url, &headers)
	if err != nil {
		return nil, err
	}
	client := DoveadmClient{
		api:         api,
		verbose:     viper.GetBool("doveadm_verbose"),
		moreVerbose: viper.GetBool("doveadm_more_verbose"),
	}
	api.verbose = client.verbose
	api.moreVerbose = client.moreVerbose
	return &client, nil
}

func (c *DoveadmClient) makeRequest(command string, args *map[string]interface{}) (string, []byte, error) {
	encodedParams := []string{}
	if args != nil {
		for k, v := range *args {
			encoded, err := json.Marshal(v)
			if err != nil {
				return "", []byte{}, fmt.Errorf("JSON encoding failed: %v", err)
			}
			encodedParams = append(encodedParams, fmt.Sprintf(`"%s": %s`, k, string(encoded)))
		}
	}
	tag := uuid.New().String()
	return tag, []byte(fmt.Sprintf(`[["%s", {%s}, "%s"]]`, command, strings.Join(encodedParams, ","), tag)), nil
}

func (c *DoveadmClient) getCommands() (string, error) {
	response := make([]interface{}, 0)
	c.api.verbose = true
	text, err := c.api.Get("/doveadm/v1", &response)
	if err != nil {
		return "", fmt.Errorf("doveadm Post failed: %v", err)
	}
	return text, nil
}

func (c *DoveadmClient) parseResponse(requestTag string, responseList *[]interface{}) (*[]interface{}, error) {

	if len(*responseList) != 1 {
		return nil, fmt.Errorf("unexpected multiple doveadm responses: %+v", *responseList)
	}

	var response []interface{}

	response = (*responseList)[0].([]interface{})

	tag := response[2]
	if tag != requestTag {
		return nil, fmt.Errorf("doveadm response tag mismatch: %s %+v", requestTag, *responseList)
	}

	label := response[0]
	switch label {
	case "doveadmResponse":
		break
	case "error":
		errorDetail := response[1].(map[string]interface{})
		return nil, fmt.Errorf("doveadm error: %+v", errorDetail)
		break
	default:
		return nil, fmt.Errorf("unrecognized doveadm response: %+v", *responseList)
	}
	var items []interface{}
	items = response[1].([]interface{})
	return &items, nil
}

func (c *DoveadmClient) sendCommand(command string, args *map[string]interface{}) (*[]interface{}, error) {
	tag, request, err := c.makeRequest(command, args)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		log.Printf("doveadm request: %v\n", string(request))
	}
	var response []interface{}
	_, err = c.api.Post("/doveadm/v1", &request, &response, nil)
	if err != nil {
		return nil, fmt.Errorf("doveadm Post failed: %v", err)
	}
	if c.verbose {
		log.Printf("doveadm response: %v\n", response)
	}
	responses, err := c.parseResponse(tag, &response)
	if err != nil {
		return nil, err
	}
	return responses, nil
}

func (c *DoveadmClient) Reload() error {
	_, err := c.sendCommand("reload", nil)
	if err != nil {
		return fmt.Errorf("reload failed: %v", err)
	}
	return err
}

func (c *DoveadmClient) MailboxList(user string) ([]string, error) {
	args := map[string]interface{}{"user": user}
	results, err := c.sendCommand("mailboxList", &args)
	if err != nil {
		return []string{}, fmt.Errorf("mailboxList failed: (user %s): %v", user, err)
	}
	mailboxes := make([]string, len(*results))
	for i, result := range *results {
		result := result.(map[string]interface{})
		mailboxes[i] = result["mailbox"].(string)
	}
	return mailboxes, nil
}

func (c *DoveadmClient) MessageAddFlag(user, mailbox, messageId, flag string) error {
	args := map[string]interface{}{
		"user":  user,
		"flag":  []string{flag},
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand("flagsAdd", &args)
	if err != nil {
		return fmt.Errorf("flagsAdd failed: (user %s mailbox %s messageId %s flag %s): %v", user, mailbox, messageId, flag, err)
	}
	return nil
}

func (c *DoveadmClient) MessageRemoveFlag(user, mailbox, messageId, flag string) error {
	args := map[string]interface{}{
		"user":  user,
		"flag":  []string{flag},
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand("flagsRemove", &args)
	if err != nil {
		return fmt.Errorf("flagsRemove failed: (user %s mailbox %s messageId %s flag %s): %v", user, mailbox, messageId, flag, err)
	}
	return nil
}

func (c *DoveadmClient) MessageExpunge(user, mailbox, messageId string) error {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand("expunge", &args)
	if err != nil {
		return fmt.Errorf("expunge failed: (user %s mailbox %s messageId %s): %v", user, mailbox, messageId, err)
	}
	return nil
}

func (c *DoveadmClient) MessageMove(user, dstMailbox, srcMailbox, messageId string) error {
	args := map[string]interface{}{
		"user":               user,
		"destinationMailbox": dstMailbox,
		"query":              []string{"MAILBOX", srcMailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand("move", &args)
	if err != nil {
		return fmt.Errorf("move failed: (user %s dst %s src %s messageId %s): %v", user, dstMailbox, srcMailbox, messageId, err)
	}
	return err
}

func (c *DoveadmClient) MailboxExpunge(user, mailbox string) error {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox},
	}
	_, err := c.sendCommand("expunge", &args)
	if err != nil {
		return fmt.Errorf("expunge failed: (user %s mailbox %s): %v", user, mailbox, err)
	}
	return nil
}

func (c *DoveadmClient) MessageDelete(user, mailbox, messageId string) error {
	err := c.MessageAddFlag(user, mailbox, messageId, "\\Deleted")
	if err != nil {
		return err
	}
	return c.MessageExpunge(user, mailbox, messageId)
}

func (c *DoveadmClient) IsMessagePresent(user, mailbox, messageId string) (bool, error) {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	results, err := c.sendCommand("search", &args)
	if err != nil {
		return false, fmt.Errorf("search failed: (user %s mailbox %s messageId %s): %v", user, mailbox, messageId, err)
	}
	return len(*results) > 0, nil
}

func (c *DoveadmClient) IsMailboxPresent(user, mailbox string) (bool, error) {
	boxen, err := c.MailboxList(user)
	if err != nil {
		return false, err
	}
	for _, name := range boxen {
		if name == mailbox {
			return true, nil
		}
	}
	return false, nil
}

func (c *DoveadmClient) MailboxCreate(user, mailbox string, mustNotExist, subscribe bool) error {
	present, err := c.IsMailboxPresent(user, mailbox)
	if err != nil {
		return err
	}
	if present {
		if mustNotExist {
			return fmt.Errorf("user %s mailbox %s exists", user, mailbox)
		}
		return nil
	}
	args := map[string]interface{}{
		"user":          user,
		"mailbox":       mailbox,
		"subscriptions": subscribe,
	}
	_, err = c.sendCommand("mailboxCreate", &args)
	if err != nil {
		return fmt.Errorf("mailboxCreate failed: (user %s mailbox %s): %v", user, mailbox, err)
	}
	return nil
}

func (c *DoveadmClient) MailboxDelete(user, mailbox string, mustExist bool) error {

	exists, err := c.IsMailboxPresent(user, mailbox)
	if err != nil {
		return err
	}
	if !exists {
		if mustExist {
			return fmt.Errorf("user %s mailbox %s not found", user, mailbox)
		}
		return nil
	}
	empty, err := c.IsMailboxEmpty(user, mailbox)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("user %s mailbox %s not empty", user, mailbox)
	}
	args := map[string]interface{}{
		"user":          user,
		"requireEmpty":  true,
		"subscriptions": true,
		"recursive":     false,
		"mailbox":       []string{mailbox},
	}
	_, err = c.sendCommand("mailboxDelete", &args)
	if err != nil {
		return fmt.Errorf("mailboxDelete failed: (user %s mailbox %s): %v", user, mailbox, err)
	}
	return nil
}

func (c *DoveadmClient) IsMailboxEmpty(user, mailbox string) (bool, error) {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox},
	}
	results, err := c.sendCommand("search", &args)
	if err != nil {
		return false, fmt.Errorf("search failed: (user %s mailbox %s): %v", user, mailbox, err)
	}
	return len(*results) == 0, nil
}
