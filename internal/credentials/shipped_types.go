package credentials

// ShippedTypes is the canonical list of rotation connectors this build ships.
//
// It exists because the figure drifted: the field test guide promised six while
// the binary registered eight and the console offered eight. Nothing was wrong
// with the code. The number was simply written down in three places and only
// two of them were ever updated.
//
// This slice is the one place. shipped_types_test.go asserts it against the
// rotators that actually compile, against the console's dropdown, and against
// the number printed in the docs, so the next connector cannot be added
// without all three moving together.
var ShippedTypes = []string{
	"aws_iam",
	"directory",
	"gcp_sa",
	"generate_only",
	"mysql",
	"postgres",
	"ssh",
	"ssh_key",
}
