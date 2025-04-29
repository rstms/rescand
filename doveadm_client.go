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
	api     *APIClient
	verbose bool
	debug   bool
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
		api:     api,
		verbose: viper.GetBool("doveadm_verbose"),
		debug:   viper.GetBool("doveadm_debug"),
	}
	api.verbose = client.verbose
	api.debug = client.debug
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
	text, err := c.api.Get("/doveadm/v1", &response)
	if err != nil {
		return "", fmt.Errorf("doveadm Post failed: %v", err)
	}
	return text, nil
}

func (c *DoveadmClient) parseResponse(requestTag string, responseList *[]interface{}) (*[]interface{}, error) {

	if len(*responseList) != 1 {
		return nil, fmt.Errorf("doveadm: unexpected multiple responses: %+v", *responseList)
	}

	var response []interface{}

	response = (*responseList)[0].([]interface{})

	tag := response[2]
	if tag != requestTag {
		return nil, fmt.Errorf("doveadm: tag mismatch: %s %+v", requestTag, *responseList)
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
		return nil, fmt.Errorf("doveadm: unrecognized response: %+v", *responseList)
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
		return nil, fmt.Errorf("doveadm request failed: %v", err)
	}
	return responses, nil
}

func (c *DoveadmClient) Reload() error {
	_, err := c.sendCommand("reload", nil)
	return err
}

func (c *DoveadmClient) MailboxList(user string) (*[]string, error) {
	args := map[string]interface{}{"user": user}
	results, err := c.sendCommand("mailboxList", &args)
	if err != nil {
		return nil, err
	}
	mailboxes := make([]string, len(*results))
	for i, result := range *results {
		result := result.(map[string]interface{})
		mailboxes[i] = result["mailbox"].(string)
	}
	return &mailboxes, nil
}

func (c *DoveadmClient) MessageSetFlag(user, mailbox, messageId, flag string, seen bool) error {
	command := "flagsAdd"
	if !seen {
		command = "flagsRemove"
	}
	args := map[string]interface{}{
		"user":  user,
		"flag":  []string{flag},
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand(command, &args)
	return err
}

func (c *DoveadmClient) MessageExpunge(user, mailbox, messageId string) error {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox, "HEADER", "MESSAGE-ID", messageId},
	}
	_, err := c.sendCommand("expunge", &args)
	return err
}

func (c *DoveadmClient) MailboxExpunge(user, mailbox string) error {
	args := map[string]interface{}{
		"user":  user,
		"query": []string{"MAILBOX", mailbox},
	}
	_, err := c.sendCommand("expunge", &args)
	return err
}

func (c *DoveadmClient) MessageDelete(user, mailbox, messageId string) error {
	err := c.MessageSetFlag(user, mailbox, messageId, "\\Deleted", true)
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
		return false, err
	}
	return len(*results) > 0, nil
}
