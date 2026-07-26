use crate::PrfVisitorError;

/// A fully resolved node supplied to sequence and map visitors.
///
/// Visitors may consume each child with a different visitor, allowing a
/// handwritten record to produce heterogeneous owned output from one batch.
pub enum ResolvedPrf<Block, Passthrough> {
    Block(Block),
    Sequence(Vec<ResolvedPrf<Block, Passthrough>>),
    Map(Vec<(String, ResolvedPrf<Block, Passthrough>)>),
    Absent,
    Passthrough(Passthrough),
}

impl<Block, Passthrough> ResolvedPrf<Block, Passthrough> {
    pub fn visit<V>(self, visitor: V) -> Result<V::Value, PrfVisitorError>
    where
        V: PrfVisitor<Block, Passthrough>,
    {
        match self {
            Self::Block(block) => visitor.visit_block(block),
            Self::Sequence(values) => visitor.visit_seq(SeqAccess::new(values)),
            Self::Map(entries) => visitor.visit_map(MapAccess::new(entries)),
            Self::Absent => visitor.visit_absent(),
            Self::Passthrough(value) => visitor.visit_passthrough(value),
        }
    }
}

/// Pull-style access to resolved sequence children.
pub struct SeqAccess<Block, Passthrough> {
    values: std::vec::IntoIter<ResolvedPrf<Block, Passthrough>>,
}

impl<Block, Passthrough> SeqAccess<Block, Passthrough> {
    pub fn new(values: Vec<ResolvedPrf<Block, Passthrough>>) -> Self {
        Self {
            values: values.into_iter(),
        }
    }

    pub fn next_node(&mut self) -> Option<ResolvedPrf<Block, Passthrough>> {
        self.values.next()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.len() == 0
    }
}

impl<Block, Passthrough> Iterator for SeqAccess<Block, Passthrough> {
    type Item = ResolvedPrf<Block, Passthrough>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_node()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

impl<Block, Passthrough> ExactSizeIterator for SeqAccess<Block, Passthrough> {}

/// Pull-style access to resolved string-keyed map children.
pub struct MapAccess<Block, Passthrough> {
    entries: std::vec::IntoIter<(String, ResolvedPrf<Block, Passthrough>)>,
}

impl<Block, Passthrough> MapAccess<Block, Passthrough> {
    pub fn new(entries: Vec<(String, ResolvedPrf<Block, Passthrough>)>) -> Self {
        Self {
            entries: entries.into_iter(),
        }
    }

    pub fn next_entry(&mut self) -> Option<(String, ResolvedPrf<Block, Passthrough>)> {
        self.entries.next()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }
}

impl<Block, Passthrough> Iterator for MapAccess<Block, Passthrough> {
    type Item = (String, ResolvedPrf<Block, Passthrough>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl<Block, Passthrough> ExactSizeIterator for MapAccess<Block, Passthrough> {}

#[cfg(test)]
mod access_tests {
    use super::{MapAccess, ResolvedPrf, SeqAccess};

    #[test]
    fn sequence_access_reports_its_exact_remaining_length() {
        let mut seq = SeqAccess::<u8, ()>::new(vec![ResolvedPrf::Block(1), ResolvedPrf::Block(2)]);

        assert_eq!(seq.len(), 2);
        assert_eq!(seq.size_hint(), (2, Some(2)));
        assert!(!seq.is_empty());
        assert!(seq.next().is_some());
        assert_eq!(seq.len(), 1);
        assert!(seq.next().is_some());
        assert_eq!(seq.size_hint(), (0, Some(0)));
        assert!(seq.is_empty());
    }

    #[test]
    fn map_access_reports_its_exact_remaining_length() {
        let mut map = MapAccess::<u8, ()>::new(vec![
            (String::from("one"), ResolvedPrf::Block(1)),
            (String::from("two"), ResolvedPrf::Block(2)),
        ]);

        assert_eq!(map.len(), 2);
        assert_eq!(map.size_hint(), (2, Some(2)));
        assert!(!map.is_empty());
        assert!(map.next().is_some());
        assert_eq!(map.len(), 1);
        assert!(map.next().is_some());
        assert_eq!(map.size_hint(), (0, Some(0)));
        assert!(map.is_empty());
    }
}

/// Interprets a resolved PRF result.
pub trait PrfVisitor<Block, Passthrough>: Sized + 'static {
    type Value: Send + 'static;

    fn visit_block(self, _block: Block) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }

    fn visit_seq(
        self,
        _seq: SeqAccess<Block, Passthrough>,
    ) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }

    fn visit_map(
        self,
        _map: MapAccess<Block, Passthrough>,
    ) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }

    fn visit_absent(self) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }

    /// Passthrough is an explicit non-secret channel. It receives no PRF
    /// protection and must not carry keys, plaintexts, or credentials.
    fn visit_passthrough(self, _value: Passthrough) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }
}

/// Visitor that returns one raw backend block.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockVisitor;

impl<Block, Passthrough> PrfVisitor<Block, Passthrough> for BlockVisitor
where
    Block: Send + 'static,
{
    type Value = Block;

    fn visit_block(self, block: Block) -> Result<Self::Value, PrfVisitorError> {
        Ok(block)
    }
}

/// Identity visitor that preserves a resolved node's structural shape.
///
/// Backend sequence and map drivers use this visitor to collect child
/// programs as [`ResolvedPrf`] nodes before the caller's final visitor is
/// applied.
impl<Block, Passthrough> PrfVisitor<Block, Passthrough> for ResolvedVisitor
where
    Block: Send + 'static,
    Passthrough: Send + 'static,
{
    type Value = ResolvedPrf<Block, Passthrough>;

    fn visit_block(self, block: Block) -> Result<Self::Value, PrfVisitorError> {
        Ok(ResolvedPrf::Block(block))
    }

    fn visit_seq(self, seq: SeqAccess<Block, Passthrough>) -> Result<Self::Value, PrfVisitorError> {
        Ok(ResolvedPrf::Sequence(seq.collect()))
    }

    fn visit_map(self, map: MapAccess<Block, Passthrough>) -> Result<Self::Value, PrfVisitorError> {
        Ok(ResolvedPrf::Map(map.collect()))
    }

    fn visit_absent(self) -> Result<Self::Value, PrfVisitorError> {
        Ok(ResolvedPrf::Absent)
    }

    fn visit_passthrough(self, value: Passthrough) -> Result<Self::Value, PrfVisitorError> {
        Ok(ResolvedPrf::Passthrough(value))
    }
}

#[derive(Clone, Copy)]
pub struct ResolvedVisitor;
