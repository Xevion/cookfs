# Lists every entry of a cookfs archive as upstream cookfs reads it.
#
# Usage: tclsh dump.tcl legacy|current LIBRARY ARCHIVE ?PASSWORD?
#
# One line per entry, tab-separated: kind, size, mtime, CRC-32 of the contents
# (or "-" for a directory), and the path. Kind is `file`, `dir`, or `unaddressable`
# for an entry whose name holds a slash, which upstream lists but cannot open. Upstream does every structural step;
# this script only finds the trailer and walks the tree.

lassign $argv flavor library archive password
load $library Cookfs
fconfigure stdout -encoding utf-8 -translation lf

# BitRock fills the legacy custom compression slot with an `.lzma`-alone stream.
# The page goes through a file rather than xz's stdin: writing a whole page into
# the pipe before reading any output deadlocks once xz fills its stdout buffer.
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

# Upstream's own search looks only near the end of the file, and installers append
# more after the archive, so when it fails, try each signature from the end with an
# explicit end offset until upstream accepts one. The current tree's memory-mapped
# path refuses an end offset within one suffix of the file's end, which is why its
# own search goes first.
proc open_archive {path signature opener} {
    if {![catch {{*}$opener {}} handle]} {
        return $handle
    }
    set f [open $path rb]
    set size [file size $path]
    set window [expr {1 << 20}]
    set end $size
    set why "no $signature bytes"
    while {$end > 0} {
        set start [expr {max(0, $end - $window)}]
        seek $f $start
        set chunk [read $f [expr {min($size - $start, $end - $start + [string length $signature] - 1)}]]
        set at [string length $chunk]
        while {[set at [string last $signature $chunk [expr {$at - 1}]]] >= 0} {
            set endoffset [expr {$start + $at + [string length $signature]}]
            if {![catch {{*}$opener $endoffset} handle]} {
                close $f
                return $handle
            }
            set why $handle
        }
        set end $start
    }
    close $f
    error "upstream accepts no $signature trailer in $path: $why"
}

# A name keeps the raw bytes it was stored with, which the output encoder mis-walks when
# they are not UTF-8, so each character is rebuilt from its code point. Tcl 8.6 cannot
# build one past U+FFFF, but those already print correctly. A lone surrogate has no
# UTF-8 form, so it is listed as U+FFFD.
proc emit {kind size mtime crc path} {
    set clean {}
    foreach ch [split $path ""] {
        scan $ch %c cp
        if {$cp > 0xFFFF} {
            append clean $ch
        } elseif {$cp >= 0xD800 && $cp <= 0xDFFF} {
            append clean \uFFFD
        } else {
            append clean [format %c $cp]
        }
    }
    puts [join [list $kind $size $mtime $crc $clean] \t]
}

proc crc {data} {
    format %08x [zlib crc32 $data]
}

proc walk_legacy {pages index dir} {
    foreach name [$index list $dir] {
        set path [expr {$dir eq "" ? $name : "$dir/$name"}]
        # A name holding a slash is listed but cannot be looked up, since `get`
        # splits its argument on slashes; report it without contents.
        if {[string first / $name] >= 0} {
            emit unaddressable - - - $path
            continue
        }
        set info [$index get $path]
        if {[llength $info] == 3} {
            lassign $info mtime size chunks
            set chan [cookfs::c::readerchannel $pages $chunks]
            fconfigure $chan -translation binary
            set data [read $chan]
            close $chan
            emit file [string length $data] $mtime [crc $data] $path
        } else {
            emit dir 0 [lindex $info 0] - $path
            walk_legacy $pages $index $path
        }
    }
}

proc walk_current {root dir} {
    set base [expr {$dir eq "" ? $root : "$root/$dir"}]
    # `-types hidden` narrows rather than widens a glob, so dot-entries need their own.
    set names [concat [glob -nocomplain -tails -directory $base *] \
        [glob -nocomplain -tails -directory $base -types hidden *]]
    foreach name [lsort -unique $names] {
        if {$name in {. ..}} continue
        set path [expr {$dir eq "" ? $name : "$dir/$name"}]
        set full "$root/$path"
        if {[file isdirectory $full]} {
            emit dir 0 [file mtime $full] - $path
            walk_current $root $path
        } else {
            set f [open $full rb]
            set data [read $f]
            close $f
            emit file [string length $data] [file mtime $full] [crc $data] $path
        }
    }
}

switch -- $flavor {
    legacy {
        set pages [open_archive $archive CFS0002 [list apply {{archive endoffset} {
            set at [expr {$endoffset eq "" ? {} : [list -endoffset $endoffset]}]
            # Legacy caches no pages by default, so every file sharing a page would
            # decompress it again; a few pages cover reads made in page order.
            cookfs::c::pages -readonly -cachesize 4 -compression custom \
                -decompresscommand lzma_decompress {*}$at $archive
        }} $archive]]
        walk_legacy $pages [cookfs::c::fsindex [$pages index]] ""
    }
    current {
        set options [list -readonly]
        if {$password ne ""} {
            lappend options -password $password
        }
        set mount /oracle
        open_archive $archive CFS0003 [list apply {{options archive mount endoffset} {
            set at [expr {$endoffset eq "" ? {} : [list -endoffset $endoffset]}]
            cookfs::Mount {*}$options {*}$at $archive $mount
        }} $options $archive $mount]
        walk_current $mount ""
    }
    default {
        error "flavor must be legacy or current, not $flavor"
    }
}
