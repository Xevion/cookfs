//! Reader for BitRock and VMware InstallBuilder installers.

#[cfg(test)]
mod tests {
    use assert2::check;

    #[test]
    fn smoke() {
        check!(size_of::<usize>() >= 4);
    }
}
