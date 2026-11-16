# Writes the fixture archives the sample corpus lacks, using upstream cookfs itself.
#
# Usage: tclsh fixtures.tcl legacy|current LIBRARY OUTDIR
#
# Most fixtures hold the same tree, built to reach the cases a reader must get
# right: a file spanning several pages, small files sharing one page, an empty
# file, deep nesting and a dot-file. Each fixture name says what varies. The
# rest stress one shape each: thousands of files, tiny pages, shared pages,
# hostile names, extreme mtimes, metadata, and archives wrapped in other bytes.
#
# Archives a listing cannot describe go to OUTDIR/unlisted without being
# printed: encrypted ones, which a reader is only expected to refuse, and names
# holding a newline, which would split a listing line.

lassign $argv flavor library outdir
load $library Cookfs
file mkdir $outdir

# Deterministic bytes: a linear congruential stream, so fixtures rebuild identically.
proc noise {seed n} {
    set out {}
    for {set i 0} {$i < $n} {incr i} {
        set seed [expr {($seed * 1103515245 + 12345) & 0x7fffffff}]
        append out [binary format c [expr {$seed >> 16}]]
    }
    return $out
}

proc tree {} {
    set text [string repeat "cookfs fixture line, compressible on purpose.\n" 600]
    list \
        readme.txt 1700000000 [string range $text 0 2047] \
        data/random.bin 1700000001 [noise 7 20000] \
        data/text.log 1700000002 $text \
        data/empty 1700000003 {} \
        nested/a/b/c/deep.txt 1700000004 "deep\n" \
        .hidden 1700000005 "dot-file\n" \
        small/s1.txt 1700000006 "one\n" \
        small/s2.txt 1700000007 "two two\n" \
        small/s3.txt 1700000008 [noise 3 300]
}

# Thousands of small files over a few dozen directories, each with its own contents.
proc many {} {
    set out {}
    for {set d 0} {$d < 20} {incr d} {
        for {set f 0} {$f < 100} {incr f} {
            lappend out [format d%02d/f%03d.txt $d $f] [expr {1700000000 + $d * 100 + $f}] \
                "file $f of directory $d\n"
        }
    }
    return $out
}

# Many files with identical contents, which upstream stores once in a shared page.
#
# The page-sized files come first, so the legacy writer's pages stay aligned to them.
proc dedup {} {
    set page [noise 11 4096]
    set out {}
    for {set i 0} {$i < 64} {incr i} {
        lappend out [format same/page%02d.bin $i] 1700000000 $page
    }
    for {set i 0} {$i < 64} {incr i} {
        lappend out [format same/small%02d.txt $i] 1700000000 "identical small file\n"
    }
    lappend out other.bin 1700000000 [noise 12 4096]
    return $out
}

# One file far larger than a page, so it spans hundreds of them.
proc large {} {
    set text {}
    for {set i 0} {$i < 5000} {incr i} {
        append text "line $i of a file much larger than one page\n"
    }
    list big/large.txt 1700000000 $text tail.txt 1700000001 "after the large file\n"
}

# Modification times at and past the edges of the 64-bit field.
proc mtimes {} {
    list \
        min -9223372036854775808 min \
        minus-one -1 minus-one \
        zero 0 zero \
        y2038 2147483648 y2038 \
        far 253402300799 far \
        max 9223372036854775807 max
}

# Legacy: cut the files, in order, into fixed-size pages, as cookfs's writer does.
#
# OPTS may hold `files` (defaults to the shared tree), `pageopts` (extra
# arguments for the pages object) and `metadata` (key/value pairs).
proc legacy {path compression hash pagesize {opts {}}} {
    set files [expr {[dict exists $opts files] ? [dict get $opts files] : [tree]}]
    set pageopts [expr {[dict exists $opts pageopts] ? [dict get $opts pageopts] : {}}]
    file delete $path
    set pages [cookfs::c::pages -readwrite -compression $compression {*}$pageopts $path]
    $pages hash $hash
    set index [cookfs::c::fsindex]

    set buffer {}
    set pending {}
    set flush {
        if {[string length $buffer] > 0} {
            set page [$pages add $buffer]
            foreach {file offset size} $pending {
                dict lappend chunks $file $page $offset $size
            }
            set buffer {}
            set pending {}
        }
    }
    set chunks [dict create]
    foreach {name mtime data} $files {
        dict set chunks $name {}
        set at 0
        while {$at < [string length $data]} {
            set room [expr {$pagesize - [string length $buffer]}]
            set piece [string range $data $at [expr {$at + $room - 1}]]
            lappend pending $name [string length $buffer] [string length $piece]
            append buffer $piece
            incr at [string length $piece]
            if {[string length $buffer] >= $pagesize} $flush
        }
    }
    eval $flush

    foreach {name mtime data} $files {
        set dir [file dirname $name]
        set parts {}
        foreach part [file split $dir] {
            if {$part eq "."} continue
            lappend parts $part
            set sub [join $parts /]
            if {[catch {$index get $sub}]} {
                $index set $sub 1690000000
            }
        }
        $index set $name $mtime [dict get $chunks $name]
    }
    if {[dict exists $opts metadata]} {
        foreach {key value} [dict get $opts metadata] {
            $index setmetadata $key $value
        }
    }
    $pages index [$index export]
    $pages close
}

# Legacy entries set straight into the fsindex, so a name reaches it unsplit and unnormalized.
proc legacy_names {path names} {
    file delete $path
    set pages [cookfs::c::pages -readwrite -compression zlib $path]
    set index [cookfs::c::fsindex]
    set i 0
    foreach name $names {
        set data "contents of entry $i\n"
        set page [$pages add $data]
        $index set $name [expr {1700000000 + $i}] [list $page 0 [string length $data]]
        incr i
    }
    # A chain of directories far deeper than a real install tree.
    set deep {}
    for {set d 0} {$d < 100} {incr d} {
        lappend deep [format d%02d $d]
        $index set [join $deep /] 1690000000
    }
    set data "at the bottom\n"
    $index set [join [concat $deep bottom.txt] /] 1700000000 [list [$pages add $data] 0 [string length $data]]
    $pages index [$index export]
    $pages close
}

# One fsindex entry, as raw bytes: a file over BLOCKS, a flat list of page, offset, size.
proc raw_entry {name blocks} {
    set out [binary format c [string length $name]]
    append out $name \0 [binary format WI 1700000000 [expr {[llength $blocks] / 3}]]
    foreach v $blocks {
        append out [binary format I $v]
    }
    return $out
}

# A legacy archive whose fsindex is BODY as given, for names no Tcl string can reach the writer with.
proc legacy_crafted {path children body} {
    file delete $path
    set pages [cookfs::c::pages -readwrite -compression zlib $path]
    $pages add "abcdefghij"
    $pages index "CFS2.200[binary format I $children]$body[binary format I 0]"
    $pages close
}

proc legacy_empty {path} {
    file delete $path
    set pages [cookfs::c::pages -readwrite -compression zlib $path]
    $pages index [[cookfs::c::fsindex] export]
    $pages close
}

# Reopens a legacy archive to drop one file, replace another and add a third, leaving orphaned pages.
proc legacy_modify {path from} {
    file copy -force $from $path
    set pages [cookfs::c::pages -readwrite -compression zlib $path]
    set index [cookfs::c::fsindex [$pages index]]
    $index unset data/random.bin
    foreach {name data} [list readme.txt "replaced readme\n" added.txt "added later\n"] {
        $index set $name 1700000100 [list [$pages add $data] 0 [string length $data]]
    }
    $pages index [$index export]
    $pages close
}

# BitRock's custom slot: a classic `.lzma`-alone stream, through xz since upstream has no codec for it.
proc lzma_compress {data} {
    set f [file tempfile path]
    fconfigure $f -translation binary
    puts -nonewline $f $data
    close $f
    set f [open |[list xz --format=lzma --compress --stdout $path] rb]
    set out [read $f]
    close $f
    file delete $path
    return $out
}

proc lzma_decompress {data} {
    set f [file tempfile path]
    fconfigure $f -translation binary
    puts -nonewline $f $data
    close $f
    set f [open |[list xz --format=lzma --decompress --stdout $path] rb]
    set out [read $f]
    close $f
    file delete $path
    return $out
}

proc slurp {path} {
    set f [open $path rb]
    set data [read $f]
    close $f
    return $data
}

proc spit {path data} {
    set f [open $path wb]
    puts -nonewline $f $data
    close $f
}

# Wraps archive A in junk that holds signature decoys a scan must step past.
proc wrap {path archive flavor} {
    set decoy [expr {$flavor eq "legacy" ? "CFS0002" : "CFS0003"}]
    set prefix "[noise 21 3000]$decoy[noise 22 100]"
    set suffix "[noise 23 64]$decoy[noise 24 9]$decoy[noise 25 500]"
    spit $path "$prefix[slurp $archive]$suffix"
}

# Follows archive A with a trailer whose layout fits but whose fsindex is not a zlib stream.
proc decoy {path archive flavor} {
    set junk [noise 26 9]
    if {$flavor eq "legacy"} {
        set trailer "\x01$junk[binary format IIc 10 0 1]CFS0002"
    } else {
        set trailer "$junk[binary format ccc 1 6 0][binary format cca16II 1 6 {} 0 0]"
        append trailer "[binary format cca16II 1 6 {} 9 100]CFS0003"
    }
    spit $path "[slurp $archive][noise 27 40]$trailer"
}

# Current: write through upstream's own mounted filesystem.
proc current {path options {files {}}} {
    if {$files eq {}} {
        set files [tree]
    }
    file delete $path
    set mount /fixture
    cookfs::Mount {*}$options $path $mount
    set dirs {}
    foreach {name mtime data} $files {
        set dir [file dirname "$mount/$name"]
        file mkdir $dir
        lappend dirs $dir
        set f [open "$mount/$name" wb]
        puts -nonewline $f $data
        close $f
        file mtime "$mount/$name" $mtime
    }
    # Directory mtimes default to the moment of writing, which would move every rebuild.
    foreach dir [lsort -unique $dirs] {
        while {$dir ne $mount} {
            file mtime $dir 1690000000
            set dir [file dirname $dir]
        }
    }
    cookfs::Unmount $mount
}

proc empty_current {path options} {
    file delete $path
    cookfs::Mount {*}$options $path /fixture
    cookfs::Unmount /fixture
}

# Remounts a current archive to drop one file, replace another and add a third.
proc current_modify {path from} {
    file copy -force $from $path
    set mount /fixture
    cookfs::Mount $path $mount
    file delete "$mount/data/random.bin"
    foreach {name data} [list readme.txt "replaced readme\n" added.txt "added later\n"] {
        set f [open "$mount/$name" wb]
        puts -nonewline $f $data
        close $f
        file mtime "$mount/$name" 1700000100
    }
    file mtime "$mount/data" 1690000000
    cookfs::Unmount $mount
}

# Names a VFS path can carry, none over the 247 bytes upstream can hold.
proc current_names {} {
    set out {}
    set i 0
    foreach name [list "caf\u00e9" "\u65e5\u672c\u8a9e" "tab\there" "sp ace" "~tilde" \
            "brace\{x" "dollar\$x" "back\\slash" "semi;colon" "q\"uote" [string repeat n 247] \
            "-dash" "CFS0003" "CFS2.200"] {
        lappend out $name [expr {1700000000 + $i}] "contents of entry $i\n"
        incr i
    }
    set deep {}
    for {set d 0} {$d < 60} {incr d} {
        lappend deep [format d%02d $d]
    }
    lappend out "[join $deep /]/bottom.txt" 1700000000 "at the bottom\n"
    return $out
}

switch -- $flavor {
    legacy {
        foreach {name compression hash} {
            v2-zlib-md5 zlib md5
            v2-zlib-crc32 zlib crc32
            v2-bz2-md5 bz2 md5
            v2-none-md5 none md5
            v2-bz2-crc32 bz2 crc32
            v2-none-crc32 none crc32
        } {
            legacy [file join $outdir $name.cfs] $compression $hash 4096
            puts $name
        }
        set custom [list pageopts {-compresscommand lzma_compress -decompresscommand lzma_decompress}]
        foreach hash {md5 crc32} {
            legacy [file join $outdir v2-lzma-$hash.cfs] custom $hash 4096 $custom
            puts v2-lzma-$hash
        }

        legacy [file join $outdir v2-many.cfs] zlib md5 4096 [list files [many]]
        puts v2-many
        legacy [file join $outdir v2-tiny-pages.cfs] zlib crc32 64
        puts v2-tiny-pages
        legacy [file join $outdir v2-dedup.cfs] zlib md5 4096 [list files [dedup]]
        puts v2-dedup
        legacy [file join $outdir v2-large.cfs] zlib md5 1024 [list files [large]]
        puts v2-large
        legacy [file join $outdir v2-mtimes.cfs] zlib md5 4096 [list files [mtimes]]
        puts v2-mtimes
        legacy [file join $outdir v2-metadata.cfs] zlib md5 4096 \
            [list metadata [list cookfs.test value empty {} large [noise 31 5000]]]
        puts v2-metadata
        # Both trees size a name's buffer as `(len + 8) & 0xf8`, which is 0 from 248 bytes up.
        legacy_names [file join $outdir v2-names.cfs] [list \
            [string repeat n 247] "caf\u00e9" "nul\u0000byte" "tab\there" ".." "." \
            "~tilde" "sp ace" "CFS0002" "CFS2.200" "\u65e5\u672c\u8a9e" "trailing "]
        puts v2-names
        legacy_empty [file join $outdir v2-empty.cfs]
        puts v2-empty
        # Upstream keeps the last of two same-named siblings.
        legacy_crafted [file join $outdir v2-dup-names.cfs] 3 \
            "[raw_entry dup {0 0 3}][raw_entry other {0 3 2}][raw_entry dup {0 5 5}]"
        puts v2-dup-names
        # Upstream reads a name up to its first NUL, so this one collides with `a`.
        legacy_crafted [file join $outdir v2-raw-nul.cfs] 2 \
            "[raw_entry "a\x00b" {0 0 3}][raw_entry a {0 3 3}]"
        puts v2-raw-nul
        # Bytes that are never UTF-8 reach Tcl as one character each, so these names stay distinct.
        legacy_crafted [file join $outdir v2-latin1-names.cfs] 2 \
            "[raw_entry "\xff" {0 0 3}][raw_entry "x\xfey" {0 3 3}]"
        puts v2-latin1-names
        legacy [file join $outdir v2-always.cfs] zlib md5 4096 {pageopts -alwayscompress}
        puts v2-always

        set a [file join $outdir v2-zlib-md5.cfs]
        set b [file join $outdir v2-zlib-crc32.cfs]
        legacy_modify [file join $outdir v2-modified.cfs] $a
        puts v2-modified
        wrap [file join $outdir v2-wrapped.cfs] $a legacy
        puts v2-wrapped
        spit [file join $outdir v2-concat.cfs] "[slurp $a][slurp $b]"
        puts v2-concat
        decoy [file join $outdir v2-decoy.cfs] $a legacy
        puts v2-decoy
        # The inner archive is stored uncompressed, so its trailer sits inside the outer one's page data.
        legacy [file join $outdir v2-nested.cfs] none md5 65536 \
            [list files [list inner.cfs 1700000000 [slurp $a] after.txt 1700000001 "after\n"]]
        puts v2-nested

        set unlisted [file join $outdir unlisted]
        file mkdir $unlisted
        legacy_names [file join $unlisted v2-newline-name.cfs] [list "line\nbreak" "plain"]
    }
    current {
        set shape {-pagesize 4096 -smallfilesize 1024}
        foreach {name extra} {
            v3-none {-compression none}
            v3-zlib {-compression zlib}
            v3-bz2 {-compression bz2}
            v3-lzma {-compression lzma}
            v3-zstd {-compression zstd}
            v3-brotli {-compression brotli}
            v3-zlib-crc32 {-compression zlib -pagehash crc32}
            v3-none-crc32 {-compression none -pagehash crc32}
            v3-bz2-crc32 {-compression bz2 -pagehash crc32}
            v3-lzma-crc32 {-compression lzma -pagehash crc32}
            v3-zstd-crc32 {-compression zstd -pagehash crc32}
            v3-brotli-crc32 {-compression brotli -pagehash crc32}
            v3-zlib-9 {-compression zlib:9}
            v3-bz2-9 {-compression bz2:9}
            v3-lzma-9 {-compression lzma:9}
            v3-zstd-19 {-compression zstd:19}
            v3-brotli-11 {-compression brotli:11}
            v3-zlib-1 {-compression zlib:1}
            v3-lzma-0 {-compression lzma:0}
        } {
            current [file join $outdir $name.cfs] [concat $shape $extra]
            puts $name
        }
        empty_current [file join $outdir v3-empty.cfs] {-compression zlib}
        puts v3-empty

        current [file join $outdir v3-many.cfs] [concat $shape {-compression zlib}] [many]
        puts v3-many
        current [file join $outdir v3-tiny-pages.cfs] {-pagesize 64 -smallfilesize 16 -compression zlib}
        puts v3-tiny-pages
        current [file join $outdir v3-aggregate.cfs] \
            {-pagesize 1048576 -smallfilesize 1048576 -compression zlib}
        puts v3-aggregate
        current [file join $outdir v3-dedup.cfs] [concat $shape {-compression zlib}] [dedup]
        puts v3-dedup
        current [file join $outdir v3-large.cfs] {-pagesize 1024 -smallfilesize 256 -compression zlib} [large]
        puts v3-large
        current [file join $outdir v3-mtimes.cfs] [concat $shape {-compression zlib}] [mtimes]
        puts v3-mtimes
        current [file join $outdir v3-names.cfs] [concat $shape {-compression zlib}] [current_names]
        puts v3-names
        # Tcl stores NUL as C0 80 and a character past the BMP as a surrogate pair.
        current [file join $outdir v3-tcl-names.cfs] [concat $shape {-compression zlib}] [list \
            "nul\u0000byte" 1700000000 "nul\n" "emoji\U1F600" 1700000001 "emoji\n" plain 1700000002 "plain\n"]
        puts v3-tcl-names
        current [file join $outdir v3-metadata.cfs] [concat $shape {-compression zlib} \
            [list -setmetadata [list cookfs.test value empty {} large [noise 31 5000]]]]
        puts v3-metadata
        current [file join $outdir v3-fileset.cfs] [concat $shape {-compression zlib -fileset alpha}]
        puts v3-fileset

        set a [file join $outdir v3-zlib.cfs]
        set b [file join $outdir v3-zstd.cfs]
        wrap [file join $outdir v3-wrapped.cfs] $a current
        puts v3-wrapped
        spit [file join $outdir v3-concat.cfs] "[slurp $a][slurp $b]"
        puts v3-concat
        decoy [file join $outdir v3-decoy.cfs] $a current
        puts v3-decoy
        current_modify [file join $outdir v3-modified.cfs] $a
        puts v3-modified
        current [file join $outdir v3-nested.cfs] {-pagesize 65536 -smallfilesize 0 -compression none} \
            [list inner.cfs 1700000000 [slurp $a] after.txt 1700000001 "after\n"]
        puts v3-nested

        set unlisted [file join $outdir unlisted]
        file mkdir $unlisted
        current [file join $unlisted v3-newline-name.cfs] [concat $shape {-compression zlib}] \
            [list "line\nbreak" 1700000000 "contents of entry 0\n" plain 1700000001 "contents of entry 1\n"]
        # Upstream draws a fresh salt per write, so these never rebuild byte for byte.
        # `-encryptkey` without a password writes an unencrypted archive, so it is not here.
        foreach {name extra} {
            v3-encrypt-file {-password secret}
            v3-encrypt-key-index {-password secret -encryptkey}
        } {
            current [file join $unlisted $name.cfs] [concat $shape {-compression zlib -encryptlevel 0} $extra]
        }
    }
    default {
        error "flavor must be legacy or current, not $flavor"
    }
}
