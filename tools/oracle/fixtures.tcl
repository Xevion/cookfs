# Writes the fixture archives the sample corpus lacks, using upstream cookfs itself.
#
# Usage: tclsh fixtures.tcl legacy|current LIBRARY OUTDIR
#
# Every fixture holds the same tree, built to reach the cases a reader must get
# right: a file spanning several pages, small files sharing one page, an empty
# file, deep nesting and a dot-file. Each fixture name says what varies.

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

# Legacy: cut the files, in order, into fixed-size pages, as cookfs's writer does.
proc legacy {path compression hash pagesize} {
    file delete $path
    set pages [cookfs::c::pages -readwrite -compression $compression $path]
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
    foreach {name mtime data} [tree] {
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

    foreach {name mtime data} [tree] {
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
    $pages index [$index export]
    $pages close
}

# Current: write through upstream's own mounted filesystem.
proc current {path options} {
    file delete $path
    set mount /fixture
    cookfs::Mount {*}$options $path $mount
    foreach {name mtime data} [tree] {
        file mkdir [file dirname "$mount/$name"]
        set f [open "$mount/$name" wb]
        puts -nonewline $f $data
        close $f
        file mtime "$mount/$name" $mtime
    }
    cookfs::Unmount $mount
}

proc empty_current {path options} {
    file delete $path
    cookfs::Mount {*}$options $path /fixture
    cookfs::Unmount /fixture
}

switch -- $flavor {
    legacy {
        foreach {name compression hash} {
            v2-zlib-md5 zlib md5
            v2-zlib-crc32 zlib crc32
            v2-bz2-md5 bz2 md5
            v2-none-md5 none md5
        } {
            legacy [file join $outdir $name.cfs] $compression $hash 4096
            puts $name
        }
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
        } {
            current [file join $outdir $name.cfs] [concat $shape $extra]
            puts $name
        }
        empty_current [file join $outdir v3-empty.cfs] {-compression zlib}
        puts v3-empty
    }
    default {
        error "flavor must be legacy or current, not $flavor"
    }
}
