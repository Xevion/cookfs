//! Archive-wide metadata, and the filesets some archives keep at their root.

use positioned_io::{ReadAt, Size};
use snafu::OptionExt;

use super::Archive;
use crate::error::{Result, error as ctx};
use crate::index::{Index, NodeId};

#[cfg(doc)]
use crate::Error;

/// The metadata key a fileset archive records how its fileset is chosen under.
const FILESET_KEY: &str = "cookfs.fileset";

/// The fileset upstream activates when it cannot match one to its runtime: the first root entry written.
pub(super) fn default_fileset(index: &Index) -> Option<NodeId> {
    index
        .first_at_root
        .filter(|&idx| index.metadata(FILESET_KEY).is_some() && index.nodes[idx].is_dir())
}

impl<R: ReadAt + Size> Archive<R> {
    /// The value the fsindex records for an archive-wide metadata `key`.
    #[must_use]
    pub fn metadata(&self, key: &str) -> Option<&[u8]> {
        self.index.metadata(key)
    }

    /// Every metadata key and its value, in the order the archive first wrote them.
    pub fn metadata_entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.index
            .metadata
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// The filesets the archive holds, sorted, or none when it was not written with filesets.
    ///
    /// A fileset archive keeps one directory per fileset at its root and names
    /// how one is chosen under the `cookfs.fileset` metadata key.
    #[must_use]
    pub fn filesets(&self) -> Vec<&str> {
        if self.metadata(FILESET_KEY).is_none() {
            return Vec::new();
        }
        self.index.nodes[self.index.root]
            .children()
            .iter()
            .map(|&c| &self.index.nodes[c])
            .filter(|n| n.is_dir())
            .map(|n| n.name.as_str())
            .collect()
    }

    /// The fileset [`Self::walk`] lists, if the archive has filesets.
    ///
    /// Upstream picks one by its own Tcl version and platform unless the
    /// archive names a custom fileset, when it takes the first written. With
    /// no Tcl runtime to match, this reader always starts at the first written;
    /// [`Self::select_fileset`] picks another.
    #[must_use]
    pub fn fileset(&self) -> Option<&str> {
        self.fileset.map(|idx| self.index.nodes[idx].name.as_str())
    }

    /// Makes the fileset `name` the one [`Self::walk`] lists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSuchFileset`] unless `name` is one of [`Self::filesets`].
    pub fn select_fileset(&mut self, name: &str) -> Result<()> {
        let found = self.index.nodes[self.index.root]
            .children()
            .iter()
            .copied()
            .find(|&c| {
                let node = &self.index.nodes[c];
                node.is_dir() && node.name == name
            });
        self.fileset = Some(
            found
                .filter(|_| self.metadata(FILESET_KEY).is_some())
                .context(ctx::NoSuchFileset {
                    name: name.to_owned(),
                })?,
        );
        Ok(())
    }
}
