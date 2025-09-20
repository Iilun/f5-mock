package f5Validator

import (
	"github.com/go-playground/validator/v10"
	"github.com/iilun/f5-mock/pkg/cache"

	"path/filepath"
	"reflect"
	"sync"
)

var once sync.Once

var Validate *validator.Validate

func init() {
	Validate = validator.New(validator.WithRequiredStructEnabled())

	_ = Validate.RegisterValidation("existingcertfile", func(fl validator.FieldLevel) bool {
		switch fl.Field().Kind() {
		case reflect.String:
			// Should be a path to a certificate file
			value := fl.Field().String()
			certPath := filepath.Join("/certs", value)
			return value == "" || cache.GlobalCache.Fs.Exists(certPath)
		default:
			return false
		}
	})

	_ = Validate.RegisterValidation("existingkeyfile", func(fl validator.FieldLevel) bool {
		switch fl.Field().Kind() {
		case reflect.String:
			// Should be a path to a certificate file
			value := fl.Field().String()
			certPath := filepath.Join("/keys", value)
			return value == "" || cache.GlobalCache.Fs.Exists(certPath)
		default:
			return false
		}
	})

	_ = Validate.RegisterValidation("existingfile", func(fl validator.FieldLevel) bool {
		switch fl.Field().Kind() {
		case reflect.String:
			// Should be a path to a certificate file
			value := fl.Field().String()
			return value == "" || cache.GlobalCache.Fs.Exists(value)
		default:
			return false
		}
	})
}
