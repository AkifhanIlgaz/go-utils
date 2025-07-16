package response

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

func WithValidationErrors(validationErrors map[string]string) Option {
	return func(r *APIResponse) {
		if r.Error != nil {
			r.Error.ValidationErrors = validationErrors
		}
	}
}
