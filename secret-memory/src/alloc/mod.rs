pub mod memsec;

pub use crate::alloc::memsec::{
    memsec_box as secret_box, memsec_vec as secret_vec, MemsecAllocator as SecretAllocator,
    MemsecBox as SecretBox, MemsecVec as SecretVec,
};
