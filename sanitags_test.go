package sanitags

import (
	"os"
	"reflect"
	"regexp"
	"testing"
)

type MockSanitizeFunc func(v string) string

func MockStrictSanitizer(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	s = re.ReplaceAllString(s, "")
	return s
}

func MockUGCSanitizer(s string) string {
	re := regexp.MustCompile(`<script[^>]*>.*</script>`)
	s = re.ReplaceAllString(s, "")
	return s
}

type MockSanitizer struct {
	sanitize MockSanitizeFunc
}

func (m *MockSanitizer) Sanitize(v string) string {
	return m.sanitize(v)
}

func NewStrictPolicy() *MockSanitizer {
	return &MockSanitizer{sanitize: MockStrictSanitizer}
}

func NewUGCPolicy() *MockSanitizer {
	return &MockSanitizer{sanitize: MockUGCSanitizer}
}

func TestMain(m *testing.M) {
	Setup(Config{
		StripAllFunc: NewStrictPolicy().Sanitize,
		UGCFunc:      NewUGCPolicy().Sanitize,
	})
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestSaniTags(t *testing.T) {
	type User struct {
		ID        int      `json:"id"`
		Name      string   `json:"name" sanitize:"stripall"`
		Bio       string   `json:"bio" sanitize:"safeugc"`
		Active    bool     `json:"active"`
		Tags      []string `json:"tags" sanitize:"stripall"`
		Interests []string `json:"interests" sanitize:"safeugc"`
		Favorites []string `json:"favorites"`
	}

	input := User{
		ID:        1,
		Name:      "<h1>John Doe</h1>",
		Bio:       "<script>alert('xss')</script><b>bio</b>",
		Active:    true,
		Tags:      []string{"<script></script>tag1", "<b>tag2</b>"},
		Interests: []string{"<script>alert('xss')</script>interest1", "<b>interest2</b>"},
		Favorites: []string{"<script>alert('xss')</script>favorite1", "<b>favorite2</b>"},
	}

	err := SanitizeStruct(&input)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := User{
		ID:     1,
		Name:   "John Doe",
		Bio:    "<b>bio</b>",
		Active: true,
		Tags:   []string{"tag1", "tag2"},
		Interests: []string{
			"interest1",
			"<b>interest2</b>",
		},
		Favorites: []string{
			"<script>alert('xss')</script>favorite1",
			"<b>favorite2</b>",
		},
	}

	if !reflect.DeepEqual(input, expectedOutput) {
		t.Errorf("expected %v but got %v", expectedOutput, input)
	}
}

func TestSaniTagsNestedStruct(t *testing.T) {
	type Address struct {
		City    string `json:"city" sanitize:"stripall"`
		Country string `json:"country" sanitize:"stripall"`
	}

	type User struct {
		ID      int     `json:"id"`
		Name    string  `json:"name" sanitize:"stripall"`
		Address Address `json:"address"`
	}

	input := User{
		ID:   1,
		Name: "<h1>John Doe</h1>",
		Address: Address{
			City:    "<script></script>",
			Country: "<b>country</b>",
		},
	}

	err := SanitizeStruct(&input)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := User{
		ID:   1,
		Name: "John Doe",
		Address: Address{
			City:    "",
			Country: "country",
		},
	}

	if !reflect.DeepEqual(input, expectedOutput) {
		t.Errorf("expected %v but got %v", expectedOutput, input)
	}
}

func TestSaniTagsDeeplyNestedStruct(t *testing.T) {
	type Address struct {
		City    string `json:"city" sanitize:"stripall"`
		Country string `json:"country" sanitize:"stripall"`
	}

	type User struct {
		ID      int     `json:"id"`
		Name    string  `json:"name" sanitize:"stripall"`
		Address Address `json:"address"`
	}

	type Profile struct {
		User User `json:"user"`
	}

	input := Profile{
		User: User{
			ID:   1,
			Name: "<h1>John Doe</h1>",
			Address: Address{
				City:    "<script></script>",
				Country: "<b>country</b>",
			},
		},
	}

	err := SanitizeStruct(&input)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := Profile{
		User: User{
			ID:   1,
			Name: "John Doe",
			Address: Address{
				City:    "",
				Country: "country",
			},
		},
	}

	if !reflect.DeepEqual(input, expectedOutput) {
		t.Errorf("expected %v but got %v", expectedOutput, input)
	}
}

func TestSaniTagsInvalidPropertyType(t *testing.T) {
	type Foo struct {
		ID   int   `json:"id"`
		Tags []int `json:"tags" sanitize:"stripall"`
	}

	input := Foo{
		ID:   1,
		Tags: []int{1, 2},
	}

	err := SanitizeStruct(&input)
	if err != ErrInvalidPropertyType {
		t.Errorf("expected %v but got %v", ErrInvalidPropertyType, err)
	}

	type Bar struct {
		ID int `json:"id" sanitize:"stripall"`
	}

	input2 := Bar{
		ID: 1,
	}

	err2 := SanitizeStruct(&input2)
	if err2 != ErrInvalidPropertyType {
		t.Error(err2)
	}

	type Baz struct {
		ID  int `json:"id"`
		Foo Foo `json:"foo" sanitize:"stripall"`
	}

	input3 := Baz{
		ID: 1,
		Foo: Foo{
			ID:   1,
			Tags: []int{1, 2},
		},
	}

	err3 := SanitizeStruct(&input3)
	if err3 != ErrInvalidPropertyType {
		t.Error(err3)
	}
}

func TestSaniTagsInvalidTagValue(t *testing.T) {
	type Foo struct {
		ID   int    `json:"id"`
		Name string `json:"name" sanitize:"invalid"`
	}

	input := Foo{
		ID:   1,
		Name: "John Doe",
	}

	err := SanitizeStruct(&input)
	if err != ErrInvalidTagValue {
		t.Errorf("expected %v but got %v", ErrInvalidTagValue, err)
	}
}

func TestSaniTagsNoTag(t *testing.T) {
	type Foo struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	input := Foo{
		ID:   1,
		Name: "<h1>John Doe</h1>",
	}

	err := SanitizeStruct(&input)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := Foo{
		ID:   1,
		Name: "<h1>John Doe</h1>",
	}

	if !reflect.DeepEqual(input, expectedOutput) {
		t.Errorf("expected %v but got %v", expectedOutput, input)
	}
}
