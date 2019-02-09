use proto::rr::Record;

/// An Object Safe Lookup for Authority
pub trait LookupObject {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    fn is_empty(&self) -> bool;

    /// Return true if other records exist at this name, but none for the searched RecordType
    fn is_name_exists(&self) -> bool;

    /// This is a non-existant domain name
    fn is_nx_domain(&self) -> bool;

    /// This is a non-existant domain name
    fn is_refused(&self) -> bool;

    /// Conversion to an iterator
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a>;
}
