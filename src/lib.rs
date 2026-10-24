//! `sonus-rs`: Sub-250ms Safe Rust PipeWire to Apple AirPlay 2 / RAOP audio engine & DACP touch daemon.
#![forbid(unsafe_code)]

pub mod config;
pub mod dacp;
pub mod discovery;
pub mod error;
pub mod mpris;
pub mod pacer;
pub mod pipewire;
pub mod raop;

pub use config::SonusConfig;
pub use error::SonusError;
