//! Number-preserving wrappers for values read off the wire.
//!
//! A cookfs id byte names a closed set today, but upstream has grown that set
//! twice. Each id is therefore a newtype over its integer with named
//! constants: an unknown value keeps its number and compares by it, and only
//! the code that needs a known value refuses one.

/// Declares a newtype over an integer with named constants and a `KNOWN` table.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($repr:ty) {
            $( $(#[$const_meta:meta])* $constant:ident = $value:expr ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(transparent)]
        $vis struct $name($repr);

        impl $name {
            $( $(#[$const_meta])* pub const $constant: Self = Self($value); )*

            /// Every named value with its name, in declaration order.
            pub const KNOWN: &'static [(Self, &'static str)] =
                &[$((Self($value), stringify!($constant))),*];

            /// Wraps a value read off the wire.
            #[must_use]
            pub const fn from_raw(raw: $repr) -> Self {
                Self(raw)
            }

            /// The value as it appears on the wire.
            #[must_use]
            pub const fn raw(self) -> $repr {
                self.0
            }

            /// The name this crate gives the value, or `None` for an unknown one.
            #[must_use]
            pub const fn name(self) -> Option<&'static str> {
                let mut index = 0;
                while index < Self::KNOWN.len() {
                    if Self::KNOWN[index].0.0 == self.0 {
                        return Some(Self::KNOWN[index].1);
                    }
                    index += 1;
                }
                None
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self.name() {
                    Some(name) => write!(f, "{}::{}", stringify!($name), name),
                    None => write!(f, "{}({})", stringify!($name), self.0),
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "unknown ({})", self.0),
                }
            }
        }
    };
}

pub(crate) use wire_enum;

wire_enum! {
    /// A blob's compression id, as either format records it.
    pub struct Compression(u8) {
        /// Stored as-is.
        NONE = 0,
        /// zlib's raw deflate stream.
        ZLIB = 1,
        /// bzip2.
        BZIP2 = 2,
        /// Raw LZMA1 behind a 5-byte properties header, with no size and no end marker.
        LZMA = 3,
        /// Zstandard.
        ZSTD = 4,
        /// Brotli.
        BROTLI = 5,
        /// The current custom slot, a Tcl callback no reader outside Tcl can run.
        CUSTOM = 254,
        /// The legacy custom slot, which BitRock fills with an `.lzma`-alone stream.
        LEGACY_CUSTOM = 255,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn an_unknown_id_keeps_its_number_through_display() {
        let id = Compression::from_raw(42);
        check!(id.name().is_none());
        check!(id.raw() == 42);
        check!(id.to_string() == "unknown (42)");
    }
}
