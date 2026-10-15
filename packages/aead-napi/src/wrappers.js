// The wrapper classes for the scalars JavaScript has no type of its own
// for. Evaluated once per environment by `wrappers.rs`, which keeps the
// constructors and recognises instances with `instanceof`.
//
// A wrapper holds its text and nothing else: the text is checked, and the
// scalar built from it, in Rust when the value is encrypted, so one rule
// applies however the instance was made. `value` is an own, enumerable,
// read-only property, so `JSON.stringify`, `structuredClone` and a deep
// equality see it.
(function () {
  "use strict";
  const define = (name) => {
    const cls = {
      [name]: class {
        constructor(value) {
          if (typeof value !== "string") {
            throw new TypeError(name + " takes a string");
          }
          Object.defineProperty(this, "value", { value, enumerable: true });
        }
        toJSON() {
          return this.value;
        }
        toString() {
          return this.value;
        }
        [Symbol.for("nodejs.util.inspect.custom")]() {
          return name + "(" + this.value + ")";
        }
      },
    }[name];
    return cls;
  };
  return {
    VcDate: define("VcDate"),
    VcTimestamp: define("VcTimestamp"),
    VcDecimal: define("VcDecimal"),
    VcUuid: define("VcUuid"),
  };
})()
