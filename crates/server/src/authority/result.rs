// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error;
use std::fmt;
use std::io;

use futures::{Async, Future, Poll};

use trust_dns::op::ResponseCode;
use trust_dns_resolver::error::ResolveError;

// TODO: should this implement Failure?
/// A query could not be fullfilled
#[derive(Debug, Eq, PartialEq)]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    NameExists,
    /// There was an error performing the lookup
    ResponseCode(ResponseCode),
    /// Resolve Error
    ResolveError(String), /* TODO: what to do here? */
    /// An underlying IO error occured
    Io(String), /* TODO: what to do here? */
}

impl LookupError {
    /// Create a lookup error, speicifying that a name exists at the location, but no matching RecordType
    pub fn for_name_exists() -> Self {
        LookupError::NameExists
    }

    /// True if other records exist at the same name, but not the searched for RecordType
    pub fn is_name_exists(&self) -> bool {
        match *self {
            LookupError::NameExists => true,
            _ => false,
        }
    }

    /// This is a non-existant domain name
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            LookupError::ResponseCode(ResponseCode::NXDomain) => true,
            _ => false,
        }
    }

    /// This is a non-existant domain name
    pub fn is_refused(&self) -> bool {
        match *self {
            LookupError::ResponseCode(ResponseCode::Refused) => true,
            _ => false,
        }
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupError::NameExists => write!(f, "NameExists"),
            LookupError::ResponseCode(rc) => write!(f, "response_code: {}", rc),
            LookupError::ResolveError(e) => write!(f, "resolve_error: {}", e),
            LookupError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

// FIXME: better error impls
impl error::Error for LookupError {}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        LookupError::ResponseCode(code)
    }
}

impl From<ResolveError> for LookupError {
    fn from(e: ResolveError) -> Self {
        LookupError::ResolveError(e.to_string())
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        LookupError::ResolveError(e.to_string())
    }
}

impl From<LookupError> for io::Error {
    fn from(e: LookupError) -> Self {
        io::Error::new(io::ErrorKind::Other, Box::new(e))
    }
}

/// Result of a Lookup in the Catalog and Authority
pub type LookupResult<T> = Result<T, LookupError>;
