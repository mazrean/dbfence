package a

import (
	"encoding/gob" // want `package encoding/gob can build plan.Keyword from a runtime string`
	"encoding/json"
	"fmt"
	"reflect" // want `package reflect can build plan.Keyword from a runtime string`
	"slices"
	"unsafe" // want `package unsafe can build plan.Keyword from a runtime string`

	"github.com/mazrean/dbfence/internal/plan"
)

// Box is a generic type whose method converts a string to T.
type Box[T ~string] struct{}

// Make converts s to T.
func (Box[T]) Make(s string) T { return T(s) }

// Holder is a generic type with no conversion; a Keyword type argument
// is still reported, since its code could fill it by reflection.
type Holder[T any] struct{ v T }

type opt struct {
	name plan.Keyword
	on   bool
}

type keywords []plan.Keyword

type alias = plan.Keyword

type kptr *plan.Keyword // want `pointer to a type that contains plan.Keyword`

func (o *opt) set(b []byte) error { return json.Unmarshal(b, o) } // want `pointer to a type that contains plan.Keyword`

func takes(p *plan.Keyword) {} // want `pointer to a type that contains plan.Keyword`

func bypass(s string, k plan.Keyword, ks keywords, b []byte) {
	// Pointer conversions.
	_ = plan.SQL("", *(*plan.Keyword)(&s))                         // want `conversion to \*plan.Keyword, which contains plan.Keyword`
	_ = plan.SQL("", *(*alias)(&s))                                // want `conversion to \*alias, which contains plan.Keyword`
	_ = plan.SQL("", *(*plan.Keyword)(unsafe.Pointer(&s)))         // want `conversion to \*plan.Keyword, which contains plan.Keyword`
	_ = (*[1]plan.Keyword)(unsafe.Pointer(&s))                     // want `conversion to \*\[1\]plan.Keyword, which contains plan.Keyword`
	_ = (*struct{ k plan.Keyword })(unsafe.Pointer(&s))            // want `conversion to \*struct\{k plan.Keyword\}, which contains plan.Keyword`
	_ = unsafe.Pointer(&ks)                                        // want `unsafe.Pointer of a value that contains plan.Keyword` `taking the address of a value that contains plan.Keyword`
	_ = plan.SQL("", plan.Keyword(*(*string)(unsafe.Pointer(&s)))) // want `plan.Keyword converts a non-constant value to SQL text`

	// Generic types and functions.
	_ = plan.SQL("", Box[plan.Keyword]{}.Make(s)) // want `plan.Keyword instantiates a generic with a type argument that contains plan.Keyword`
	_ = Holder[keywords]{}                         // want `keywords instantiates a generic with a type argument that contains plan.Keyword`
	_ = Holder[func() plan.Keyword]{}              // want `func\(\) plan.Keyword instantiates a generic with a type argument that contains plan.Keyword`
	_ = Holder[map[string]opt]{}                   // want `map\[string\]opt instantiates a generic with a type argument that contains plan.Keyword`
	_ = slices.Clone(ks)                           // want `keywords instantiates a generic with a type argument that contains plan.Keyword`
	_ = Holder[string]{}

	// Decoders that fill a Keyword through a pointer.
	var dk plan.Keyword
	_ = json.Unmarshal(b, &dk) // want `taking the address of a value that contains plan.Keyword`
	_, _ = fmt.Sscan(s, &dk)   // want `taking the address of a value that contains plan.Keyword`
	var o opt
	_ = json.Unmarshal(b, &o)   // want `taking the address of a value that contains plan.Keyword`
	_ = json.Unmarshal(b, &ks)  // want `taking the address of a value that contains plan.Keyword`
	_ = &ks[0]                  // want `taking the address of a value that contains plan.Keyword`
	_ = &opt{name: "LOGIN"}     // want `taking the address of a value that contains plan.Keyword`
	_ = new(plan.Keyword)       // want `new of a type that contains plan.Keyword`
	_ = new(opt)                // want `new of a type that contains plan.Keyword`
	_ = reflect.ValueOf(&s)
	// gob decodes a registered Keyword into an interface field.
	gob.Register(plan.Keyword(""))
	var frag struct{ F plan.Fragment }
	_ = gob.NewDecoder(nil).Decode(&frag)
	_ = plan.SQL("", dk, o.name)

	// Values, same-shaped conversions and pointers to other types are fine.
	_ = keywords([]plan.Keyword{k})
	_ = []plan.Keyword(ks)
	_ = []opt{{name: "LOGIN", on: true}}
	_ = map[bool]plan.Keyword{true: " ACCOUNT UNLOCK", false: " ACCOUNT LOCK"}
	_ = &s
	_ = new(string)
	var ok *bool
	_ = ok
}
