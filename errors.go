package credentials

import "errors"

// ErrorCode is a stable, language-neutral credential failure category.
type ErrorCode string

const (
	ErrCredentialNotFound  ErrorCode = "CREDENTIAL_NOT_FOUND"
	ErrInvalidCredential   ErrorCode = "INVALID_CREDENTIAL"
	ErrAmbiguousCredential ErrorCode = "AMBIGUOUS_CREDENTIAL"
	ErrRefreshFailed       ErrorCode = "REFRESH_FAILED"
	ErrProfileConflict     ErrorCode = "PROFILE_CONFLICT"
	ErrCredentialStorage   ErrorCode = "CREDENTIAL_STORAGE_FAILED"
)

// Error is safe to show to a user and never contains credential values.
type Error struct {
	Code    ErrorCode
	message string
	cause   error
}

func (e *Error) Error() string {
	return e.message
}

func (e *Error) Unwrap() error {
	return e.cause
}

// IsError reports whether err is a Circles credential error with code.
func IsError(err error, code ErrorCode) bool {
	var credentialError *Error
	return errors.As(err, &credentialError) && credentialError.Code == code
}

func credentialError(code ErrorCode, message string) *Error {
	return &Error{Code: code, message: message}
}

func storageError(message string, cause error) error {
	var credentialFailure *Error
	if errors.As(cause, &credentialFailure) {
		return cause
	}
	return &Error{Code: ErrCredentialStorage, message: message, cause: cause}
}
