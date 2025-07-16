package response

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"reflect"
	"strings"
)

type Option func(response *APIResponse)

func WithMeta(meta *Meta) Option {
	return func(r *APIResponse) {
		r.Meta = meta
	}
}

func WithPayload(payload any) Option {
	return func(r *APIResponse) {
		r.Payload = payload
	}
}

func WithError(err *APIError) Option {
	return func(r *APIResponse) {
		r.Error = err
		r.Success = false
	}
}

func WithDetails(details ...string) Option {
	return func(r *APIResponse) {
		if r.Error != nil {
			r.Error.Details = details
		}
	}
}

func WithValidationErrors(validationErrors validator.ValidationErrors) Option {
	return func(r *APIResponse) {
		if r.Error != nil {
			errors := make(map[string]string)

			for _, fieldError := range validationErrors {
				field := strings.ToLower(fieldError.Field())
				tag := fieldError.Tag()
				param := fieldError.Param()

				switch tag {
				// Required field validation
				case "required":
					errors[field] = fmt.Sprintf("%s is required", field)

				// Format validations
				case "email":
					errors[field] = fmt.Sprintf("%s must be a valid email", field)
				case "url":
					errors[field] = fmt.Sprintf("%s must be a valid URL", field)
				case "uri":
					errors[field] = fmt.Sprintf("%s must be a valid URI", field)

				// Length validations
				case "min":
					if fieldError.Kind() == reflect.String {
						errors[field] = fmt.Sprintf("%s must be at least %s characters long", field, param)
					} else {
						errors[field] = fmt.Sprintf("%s must be at least %s", field, param)
					}
				case "max":
					if fieldError.Kind() == reflect.String {
						errors[field] = fmt.Sprintf("%s must be at most %s characters long", field, param)
					} else {
						errors[field] = fmt.Sprintf("%s must be at most %s", field, param)
					}
				case "len":
					errors[field] = fmt.Sprintf("%s must be exactly %s characters long", field, param)

				// Character type validations
				case "alpha":
					errors[field] = fmt.Sprintf("%s must contain only alphabetic characters", field)
				case "alphanum":
					errors[field] = fmt.Sprintf("%s must contain only alphanumeric characters", field)
				case "numeric":
					errors[field] = fmt.Sprintf("%s must contain only numeric characters", field)
				case "lowercase":
					errors[field] = fmt.Sprintf("%s must be in lowercase", field)
				case "uppercase":
					errors[field] = fmt.Sprintf("%s must be in uppercase", field)

				// Comparison validations
				case "gt":
					errors[field] = fmt.Sprintf("%s must be greater than %s", field, param)
				case "gte":
					errors[field] = fmt.Sprintf("%s must be greater than or equal to %s", field, param)
				case "lt":
					errors[field] = fmt.Sprintf("%s must be less than %s", field, param)
				case "lte":
					errors[field] = fmt.Sprintf("%s must be less than or equal to %s", field, param)
				case "eq":
					errors[field] = fmt.Sprintf("%s must be equal to %s", field, param)
				case "ne":
					errors[field] = fmt.Sprintf("%s must not be equal to %s", field, param)

				// Contains validations
				case "contains":
					errors[field] = fmt.Sprintf("%s must contain '%s'", field, param)
				case "containsany":
					errors[field] = fmt.Sprintf("%s must contain at least one of these characters: %s", field, param)
				case "containsrune":
					errors[field] = fmt.Sprintf("%s must contain the character '%s'", field, param)

				// Excludes validations
				case "excludes":
					errors[field] = fmt.Sprintf("%s must not contain '%s'", field, param)
				case "excludesall":
					errors[field] = fmt.Sprintf("%s must not contain any of these characters: %s", field, param)
				case "excludesrune":
					errors[field] = fmt.Sprintf("%s must not contain the character '%s'", field, param)

				// Default case
				default:
					errors[field] = fmt.Sprintf("%s failed validation for %s", field, tag)
				}
				r.Error.ValidationErrors = errors
			}
		}
	}
}
