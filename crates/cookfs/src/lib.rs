//! cookfs, the page-based Tcl virtual filesystem archive format.

#[cfg(test)]
mod tests {
    use assert2::check;

    #[test]
    fn smoke() {
        check!(size_of::<usize>() >= 4);
    }
}
