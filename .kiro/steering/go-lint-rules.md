---
description: Go coding standards enforced by golangci-lint to prevent errcheck and staticcheck violations.
inclusion: fileMatch
fileMatchPattern: "**/*.go"
---

# Go Lint Rules

This project uses `golangci-lint` with `errcheck` and `staticcheck` enabled. All code must pass with zero issues.

## errcheck: Always handle return values

### resp.Body.Close() in defer
```go
// BAD
defer resp.Body.Close()

// GOOD
defer func() { _ = resp.Body.Close() }()
```

### Non-deferred Close calls
```go
// BAD
resp.Body.Close()

// GOOD
_ = resp.Body.Close()
```

### database.Close() in defer
```go
// BAD
defer database.Close()

// GOOD
defer func() { _ = database.Close() }()
```

### w.Write in HTTP handlers
```go
// BAD
w.Write([]byte("response"))

// GOOD
_, _ = w.Write([]byte("response"))
```

### json.NewEncoder/Encoder in HTTP handlers
```go
// BAD
json.NewEncoder(w).Encode(resp)

// GOOD
_ = json.NewEncoder(w).Encode(resp)
```

### fmt.Fprint in HTTP handlers (tests)
```go
// BAD
fmt.Fprint(w, `{"status":"ok"}`)

// GOOD
_, _ = fmt.Fprint(w, `{"status":"ok"}`)
```

### json.NewDecoder in test mock servers
```go
// BAD
json.NewDecoder(r.Body).Decode(&body)

// GOOD
_ = json.NewDecoder(r.Body).Decode(&body)
```

### os.Setenv / os.Unsetenv in tests
```go
// BAD
os.Setenv("KEY", "value")
os.Unsetenv("KEY")

// GOOD
_ = os.Setenv("KEY", "value")
_ = os.Unsetenv("KEY")
```

## staticcheck: Nil pointer safety

After a nil check with `t.Fatalf`, add `return` to satisfy staticcheck (especially in `rapid` property tests where `*rapid.T` isn't recognized as terminating):

```go
// BAD
if record == nil {
    t.Fatalf("not found")
}
record.Field // SA5011: possible nil pointer dereference

// GOOD
if record == nil {
    t.Fatalf("not found")
    return
}
record.Field // staticcheck is satisfied
```

## General rules

- Every `io.Closer` in a defer must use the closure pattern or assign to `_`
- Every write to `http.ResponseWriter` must have its return value handled
- In test mock HTTP handlers, all encode/decode/write calls need `_ =` or `_, _ =`
- When in doubt, assign the return value to `_` — the linter cares, the runtime doesn't
