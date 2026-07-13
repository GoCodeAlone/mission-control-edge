package protocol

import "testing"

func TestCheckedAllocationSize(t *testing.T) {
	t.Parallel()

	if got, err := checkedAllocationSize(4, 8, 16); err != nil || got != 28 {
		t.Fatalf("checkedAllocationSize valid = %d, %v", got, err)
	}
	if _, err := checkedAllocationSize(-1); err == nil {
		t.Fatal("checkedAllocationSize accepted a negative part")
	}
	maxInt := int(^uint(0) >> 1)
	if _, err := checkedAllocationSize(maxInt, 1); err == nil {
		t.Fatal("checkedAllocationSize accepted an overflowing sum")
	}
}
