package response

import (
	"time"
)

type APIResponse struct {
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Payload   any       `json:"payload,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Error     *APIError `json:"error,omitempty"`
	Meta      *Meta     `json:"meta,omitempty"`
}

type Meta struct {
	Page       int `json:"page,omitempty"`
	PageSize   int `json:"page_size,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

type APIError struct {
	Code             int               `json:"code"`
	Message          string            `json:"message,omitempty"`
	Details          []string          `json:"details,omitempty"`
	ValidationErrors map[string]string `json:"validation_errors,omitempty"`
}

func Success(message string, opts ...Option) APIResponse {
	res := APIResponse{
		Success:   true,
		Message:   message,
		Timestamp: time.Now(),
	}

	for _, opt := range opts {
		opt(&res)
	}

	return res
}

func Error(code int, message string, opts ...Option) APIResponse {
	res := APIResponse{
		Success:   false,
		Message:   message,
		Timestamp: time.Now(),
		Error: &APIError{
			Code:    code,
			Message: message,
		},
	}

	for _, opt := range opts {
		opt(&res)
	}

	return res
}
