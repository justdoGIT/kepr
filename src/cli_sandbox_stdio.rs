//! Standard streams must not carry host directory or socket capabilities.

pub(crate) fn validate() -> Result<(), &'static str> {
    for fd in 0..=2 {
        // SAFETY: zero initialization is valid for libc's plain stat structure.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes only to the valid stat allocation.
        if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
            return Err(
                "private workspace standard streams must be valid files, pipes or terminals",
            );
        }
        let kind = metadata.st_mode & libc::S_IFMT;
        if kind == libc::S_IFREG || kind == libc::S_IFIFO {
            continue;
        }
        if kind == libc::S_IFCHR {
            // SAFETY: isatty inspects the supplied descriptor without taking ownership.
            if unsafe { libc::isatty(fd) } == 1 {
                continue;
            }
            if libc::major(metadata.st_rdev) == 1
                && matches!(libc::minor(metadata.st_rdev), 3 | 5 | 8 | 9)
            {
                continue;
            }
        }
        return Err("private workspace standard streams cannot be directories, sockets or unapproved devices");
    }
    Ok(())
}
