//! Metakit, an embedded database format used as a Tcl virtual filesystem.

#[cfg(test)]
mod tests {
    use assert2::check;

    #[test]
    fn smoke() {
        check!(size_of::<usize>() >= 4);
    }
}
