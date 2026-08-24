package control

import (
	"reflect"
	"testing"
)

// gomobileSafe reports whether t is a type gomobile bind can carry across the
// language boundary: string, bool, the sized int/float/byte kinds, []byte, or
// error. (gomobile also supports *struct bound types, but the control facade
// deliberately restricts itself to primitives + JSON strings so the mobile and
// desktop transports stay identical.)
func gomobileSafe(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64:
		return true
	case reflect.Slice:
		return t.Elem().Kind() == reflect.Uint8 // []byte
	case reflect.Interface:
		return t == reflect.TypeOf((*error)(nil)).Elem() // error
	default:
		return false
	}
}

// TestEngineSignaturesAreGomobileSafe is a compile-/run-time guard that every
// exported *Engine method takes and returns only gomobile-friendly types, so
// Phase 2 can `gomobile bind` the SAME facade. If someone adds a method that
// takes a struct/map/channel/etc, this fails and points at the offender.
func TestEngineSignaturesAreGomobileSafe(t *testing.T) {
	et := reflect.TypeOf(&Engine{})
	errType := reflect.TypeOf((*error)(nil)).Elem()

	for i := 0; i < et.NumMethod(); i++ {
		m := et.Method(i)
		if !m.IsExported() {
			continue
		}
		mt := m.Type
		// Params: index 0 is the receiver; skip it.
		for p := 1; p < mt.NumIn(); p++ {
			if in := mt.In(p); !gomobileSafe(in) {
				t.Errorf("method %s: parameter %d has non-gomobile-safe type %s", m.Name, p, in)
			}
		}
		// Returns: must be (T, error) or (error) or (T) with gomobile-safe T.
		nout := mt.NumOut()
		if nout == 0 {
			t.Errorf("method %s: expected at least one return value", m.Name)
			continue
		}
		if nout > 2 {
			t.Errorf("method %s: expected at most 2 return values, got %d", m.Name, nout)
		}
		for o := 0; o < nout; o++ {
			out := mt.Out(o)
			if out == errType {
				continue
			}
			if !gomobileSafe(out) {
				t.Errorf("method %s: return %d has non-gomobile-safe type %s", m.Name, o, out)
			}
		}
		// If there are 2 returns, the last must be error.
		if nout == 2 && mt.Out(1) != errType {
			t.Errorf("method %s: 2nd return must be error, got %s", m.Name, mt.Out(1))
		}
	}
}
