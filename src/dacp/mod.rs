//! Apple DACP (Digital Audio Control Protocol) server and DMAP binary tags.

pub mod dmap;
pub mod server;

pub use dmap::{build_playstatus_update, decode_dmap_tags, DmapTag, PlaybackState};
pub use server::{DacpCommand, DacpServer};
