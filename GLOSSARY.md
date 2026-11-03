# Vitamin C

Vitamin C is a suite of crates for cryptography and handling sensitive data. This glossary names the concepts specific to it.

## Language

### Serialized plaintext

**Profile**:
A set of rules for turning a value into nodes and back. There are two: the transport profile, for values in flight between a host and a guest that ship together, and the storage profile, for values that are kept.
_Avoid_: Format, codec, mode

**Frame**:
A value's plaintext as the transport profile writes it. It carries no version and makes no compatibility promise.
_Avoid_: Payload, message

**Blob**:
A value's plaintext as the storage profile writes it: a versioned header, then one node. Its bytes are a compatibility promise.
_Avoid_: Record, stored frame

**Node**:
One tagged value inside a frame or blob: a scalar, an array, an object or map, or a presence marker.
_Avoid_: Element, item, token

**Refusal**:
A value that a profile declines to read or write, together with where in the value it happened. It never contains the value itself or any of its keys.
_Avoid_: Diagnostic, rejection, failure
