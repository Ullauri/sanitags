package sanitags

import (
	"fmt"
	"reflect"
)

var ErrInvalidTagValue = fmt.Errorf("invalid tag value")
var ErrInvalidPropertyType = fmt.Errorf("invalid property type: expected string")

func getCleansedValue(tag string, value string) (string, error) {
	var cleanedValue string
	switch TagValue(tag) {
	case StripAll:
		cleanedValue = config.StripAll(value)
	case SafeUGC:
		cleanedValue = config.SafeUGC(value)
	default:
		return "", ErrInvalidTagValue
	}

	return cleanedValue, nil
}

// SanitizeStruct takes a struct and sanitizes it based on `sanitize` tags
func SanitizeStruct(s interface{}) error {
	val := reflect.ValueOf(s).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		fieldKind := field.Kind()

		tag := fieldType.Tag.Get("sanitize")
		if tag == "" {
			if fieldKind == reflect.Struct {
				if err := SanitizeStruct(field.Addr().Interface()); err != nil {
					return err
				}
			}
			continue
		} else if fieldKind == reflect.Struct {
			return ErrInvalidPropertyType
		} else if fieldKind != reflect.String && !(fieldKind == reflect.Slice && field.Type().Elem().Kind() == reflect.String) {
			return ErrInvalidPropertyType
		}

		if fieldKind == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				cleanedValue, err := getCleansedValue(tag, field.Index(j).String())
				if err != nil {
					return err
				}
				field.Index(j).SetString(cleanedValue)
			}
		} else {
			cleanedValue, err := getCleansedValue(tag, field.String())
			if err != nil {
				return err
			}
			field.SetString(cleanedValue)
		}
	}

	return nil
}
