// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use trust_dns::op::ResponseCode;
use trust_dns::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use trust_dns_resolver::AsyncResolver;


use authority::{
    AnyRecords, AuthLookup, Authority, LookupRecords, MessageRequest, UpdateResult, ZoneType,
};

pub struct ForwardAuthority {
    origin: LowerName,
    resolver: AsyncResolver,
}

impl Authority for ForwardAuthority {
    type Lookup = AuthLookup;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    /// 
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> AuthLookup {
        self.origin.zone_of(name);
        
        unimplemented!()
        // self.resolver.lookup()
    }

    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> AuthLookup {
        unimplemented!()
    }

    fn add_zone_signing_key(&mut self, _signer: Signer) -> DnsSecResult<()> {
        Err("DNSSEC zone signing not supported in Forwarder".into())
    }

    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Err("DNSSEC zone signing not supported in Forwarder".into())
    }
}