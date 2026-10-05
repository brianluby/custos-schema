//! OCSF `_id` enum machinery.
//!
//! OCSF normatively defines `0 = Unknown` and `99 = Other` on most enums.
//! An out-of-vocabulary integer is a third case — a value this library
//! version doesn't know — kept lossless as `Unrecognized(i32)`.

macro_rules! ocsf_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident = $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            /// OCSF normative Unknown (0).
            Unknown,
            $($(#[$vmeta])* $variant,)+
            /// OCSF normative Other (99).
            Other,
            /// Value outside this library's vocabulary (forward compatibility).
            Unrecognized(i32),
        }

        impl $name {
            /// Normative variant values, excluding Unknown (0) and Other (99).
            pub const KNOWN: &'static [i32] = &[$($value),+];
        }

        impl ::core::default::Default for $name {
            /// OCSF normative Unknown (0): the natural zero-value default,
            /// and required so this enum can sit in a non-`Option` field of
            /// a `#[derive(Default)]` struct (e.g. a required `_id` attribute).
            fn default() -> Self {
                Self::Unknown
            }
        }

        impl ::core::convert::From<i32> for $name {
            fn from(v: i32) -> Self {
                match v {
                    0 => Self::Unknown,
                    99 => Self::Other,
                    $($value => Self::$variant,)+
                    other => Self::Unrecognized(other),
                }
            }
        }

        impl ::core::convert::From<$name> for i32 {
            fn from(v: $name) -> i32 {
                match v {
                    $name::Unknown => 0,
                    $name::Other => 99,
                    $($name::$variant => $value,)+
                    $name::Unrecognized(x) => x,
                }
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_i32((*self).into())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = i32::deserialize(d)?;
                Ok(Self::from(v))
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> String {
                stringify!($name).to_string()
            }
            fn json_schema(generator: &mut ::schemars::r#gen::SchemaGenerator) -> ::schemars::schema::Schema {
                // Wire form is a plain integer; Unrecognized admits any i32,
                // so no `enum` restriction is emitted.
                <i32 as ::schemars::JsonSchema>::json_schema(generator)
            }
        }
    };
}

pub(crate) use ocsf_enum;

ocsf_enum! {
    /// Event severity (OCSF `severity_id`).
    pub enum SeverityId {
        Informational = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Critical = 5,
        Fatal = 6,
    }
}

#[cfg(test)]
mod tests {
    use super::SeverityId;

    #[test]
    fn severity_roundtrips_known_and_unrecognized() {
        assert_eq!(SeverityId::from(4), SeverityId::High);
        assert_eq!(SeverityId::from(0), SeverityId::Unknown);
        assert_eq!(SeverityId::from(99), SeverityId::Other);
        assert_eq!(SeverityId::from(1234), SeverityId::Unrecognized(1234));
        assert_eq!(i32::from(SeverityId::Unrecognized(1234)), 1234);
    }

    #[test]
    fn severity_serde_is_integer() {
        let json = serde_json::to_string(&SeverityId::Critical).unwrap();
        assert_eq!(json, "5");
        let back: SeverityId = serde_json::from_str("7777").unwrap();
        assert_eq!(back, SeverityId::Unrecognized(7777));
    }

    #[test]
    fn severity_schema_is_integer() {
        let schema = serde_json::to_value(schemars::schema_for!(SeverityId)).unwrap();
        assert_eq!(schema["type"], "integer");
    }

    #[test]
    fn known_values_exclude_unknown_and_other() {
        assert_eq!(SeverityId::KNOWN, &[1, 2, 3, 4, 5, 6]);
    }
}
