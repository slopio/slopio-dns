/// Declares an enum of known wire values plus an `Other` catch-all, with
/// lossless conversions to and from the raw integer.
///
/// Build values from integers with `From`, so that known values never end up
/// in `Other` (which would break equality).
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident: $repr:ty {
            $($(#[$vmeta:meta])* $variant:ident = $value:literal,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
            /// A value without a named variant.
            Other($repr),
        }

        impl From<$repr> for $name {
            fn from(v: $repr) -> Self {
                match v {
                    $($value => Self::$variant,)*
                    other => Self::Other(other),
                }
            }
        }

        impl From<$name> for $repr {
            fn from(v: $name) -> Self {
                match v {
                    $($name::$variant => $value,)*
                    $name::Other(other) => other,
                }
            }
        }
    };
}

wire_enum! {
    /// TYPE / QTYPE field.
    RecordType: u16 {
        A = 1,
        Ns = 2,
        Cname = 5,
        Soa = 6,
        Ptr = 12,
        Mx = 15,
        Txt = 16,
        Aaaa = 28,
        Srv = 33,
        /// EDNS pseudo-record; surfaced as [`super::Edns`], never as a record.
        Opt = 41,
        /// QTYPE only.
        Any = 255,
    }
}

wire_enum! {
    /// CLASS / QCLASS field.
    Class: u16 {
        In = 1,
        Ch = 3,
        Hs = 4,
        /// QCLASS only.
        Any = 255,
    }
}

wire_enum! {
    /// Header OPCODE, 4 bits on the wire.
    Opcode: u8 {
        Query = 0,
        IQuery = 1,
        Status = 2,
        Notify = 4,
        Update = 5,
    }
}

wire_enum! {
    /// Response code. The header holds the low 4 bits; EDNS extends it to 12.
    Rcode: u16 {
        NoError = 0,
        FormErr = 1,
        ServFail = 2,
        NxDomain = 3,
        NotImp = 4,
        Refused = 5,
        BadVers = 16,
    }
}
