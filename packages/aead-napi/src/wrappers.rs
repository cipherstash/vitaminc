//! The wrapper classes: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`.
//!
//! JavaScript has no type of its own for a calendar date, a timestamp finer
//! than a millisecond, a decimal or a UUID, so the binding represents each
//! as an instance of a small class holding its text. A class instance is
//! not a plain object, so it can never be confused with data another
//! language wrote as an ordinary one-key object (#382).
//!
//! The classes are defined by the JavaScript in `wrappers.js`, evaluated
//! once per environment, and their constructors are kept in the
//! environment's instance data. An addon exports them with
//! [`Wrappers::exports`] so applications can construct them; the walk
//! recognises instances with `instanceof`, and the build constructs them.

use napi::bindgen_prelude::{Function, FunctionRef, JsObjectValue, JsValue, Object, Unknown};
use napi::{Env, Error, Result, Status};

/// Which wrapper class a value is an instance of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    Date,
    Timestamp,
    Decimal,
    Uuid,
}

impl Wrapper {
    pub const ALL: [Wrapper; 4] = [
        Wrapper::Date,
        Wrapper::Timestamp,
        Wrapper::Decimal,
        Wrapper::Uuid,
    ];

    /// The class name, as JavaScript sees it.
    pub fn class_name(self) -> &'static str {
        match self {
            Wrapper::Date => "VcDate",
            Wrapper::Timestamp => "VcTimestamp",
            Wrapper::Decimal => "VcDecimal",
            Wrapper::Uuid => "VcUuid",
        }
    }
}

/// A wrapper class constructor: one string argument, the text.
type Constructor = FunctionRef<String, Unknown<'static>>;

/// The constructors of the wrapper classes for one environment.
pub struct Wrappers {
    constructors: [Constructor; 4],
}

const SOURCE: &str = include_str!("wrappers.js");

/// The own property a wrapper instance holds its text in.
const VALUE: &str = "value";

impl Wrappers {
    /// The wrapper classes of `env`, defined on first use.
    ///
    /// They live in the environment's instance data
    /// (`napi_set_instance_data`), which an addon that uses this crate
    /// must leave to it.
    pub fn get(env: &Env) -> Result<&'static Wrappers> {
        if let Some(wrappers) = env.get_instance_data::<Wrappers>()? {
            return Ok(&*wrappers);
        }
        let classes: Object<'_> = env.run_script(SOURCE)?;
        let mut constructors = Vec::with_capacity(Wrapper::ALL.len());
        for wrapper in Wrapper::ALL {
            let constructor: Function<'_, String, Unknown<'_>> =
                classes.get_named_property(wrapper.class_name())?;
            constructors.push(constructor.create_ref()?);
        }
        let constructors: [Constructor; 4] = constructors
            .try_into()
            .map_err(|_| Error::new(Status::GenericFailure, "wrapper classes did not define"))?;
        env.set_instance_data(Wrappers { constructors }, (), |_| {})?;
        let retained = env.get_instance_data::<Wrappers>()?.ok_or_else(|| {
            Error::new(Status::GenericFailure, "wrapper classes were not retained")
        })?;
        Ok(&*retained)
    }

    /// An object holding every class under its name, for an addon to
    /// re-export: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`.
    pub fn exports<'e>(env: &'e Env) -> Result<Object<'e>> {
        let wrappers = Self::get(env)?;
        let mut exports = Object::new(env)?;
        for wrapper in Wrapper::ALL {
            exports
                .set_named_property(wrapper.class_name(), wrappers.constructor(env, wrapper)?)?;
        }
        Ok(exports)
    }

    fn constructor<'e>(
        &self,
        env: &'e Env,
        wrapper: Wrapper,
    ) -> Result<Function<'e, String, Unknown<'e>>> {
        self.constructors[wrapper as usize].borrow_back(env)
    }

    /// Which wrapper class `value` is an instance of, if any.
    pub fn classify(&self, env: &Env, value: &Unknown<'_>) -> Result<Option<Wrapper>> {
        for wrapper in Wrapper::ALL {
            if value.instanceof(self.constructor(env, wrapper)?)? {
                return Ok(Some(wrapper));
            }
        }
        Ok(None)
    }

    /// The text a wrapper instance holds. The class keeps `value` as an
    /// own, read-only string, but an instance can be made without the
    /// constructor (`Object.create`), so the property is read as an own
    /// property and its type checked.
    pub fn text<'e>(&self, instance: &Object<'e>) -> Result<Option<Unknown<'e>>> {
        if !instance.has_own_property(VALUE)? {
            return Ok(None);
        }
        let text = crate::js::get_property_unknown(instance, VALUE)?;
        Ok((text.get_type()? == napi::ValueType::String).then_some(text))
    }

    /// A new instance of `wrapper` holding `text`.
    pub fn construct<'e>(&self, env: &'e Env, wrapper: Wrapper, text: &str) -> Result<Unknown<'e>> {
        self.constructor(env, wrapper)?
            .new_instance(text.to_owned())
    }
}
