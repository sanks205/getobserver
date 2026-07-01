package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OpenAIProvider calls the OpenAI Chat Completions API. It implements Provider.
//
// The base URL is configurable so it can be pointed at a compatible endpoint or
// a test server. Nothing here is OpenAI-specific beyond the request/response
// shape, so adding another provider means writing a sibling file, not touching
// the Explainer.
type OpenAIProvider struct {
	APIKey  string
	Model   string
	BaseURL string // defaults to https://api.openai.com/v1
	client  *http.Client
}

// NewOpenAI constructs an OpenAIProvider with sensible defaults.
func NewOpenAI(apiKey, model, baseURL string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o-mini"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: baseURL,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *OpenAIProvider) Name() string { return "openai:" + p.Model }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float32         `json:"temperature"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	ResponseFormat json.RawMessage `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete sends the prompt to the chat completions endpoint and returns the
// assistant's message content.
func (p *OpenAIProvider) Complete(ctx context.Context, req Request) (string, error) {
	if p.APIKey == "" {
		return "", fmt.Errorf("openai: missing API key")
	}

	body := chatRequest{
		Model: p.Model,
		Messages: []chatMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
		Temperature:    req.Temperature,
		MaxTokens:      req.MaxTokens,
		ResponseFormat: json.RawMessage(`{"type":"json_object"}`),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}

	var cr chatResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("openai: decoding response (status %d): %w", resp.StatusCode, err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("openai: API error: %s", cr.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai: unexpected status %d", resp.StatusCode)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response")
	}
	return cr.Choices[0].Message.Content, nil
}
