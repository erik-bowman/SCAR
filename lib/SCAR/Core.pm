#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Core
#
# DESCRIPTION
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Core;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use POSIX qw(strftime);

# ------------------------------------------------------------------------------

require Exporter;

our $VERSION = 0.01;
our @ISA = qw(Exporter);
our @EXPORT = qw(version_check);
our @EXPORT_OK = qw(timestamp);

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $result = &timestamp();
#
# DESCRIPTION
#   Returns a timestamp in the format of HH:MM:SS
#
# ------------------------------------------------------------------------------

sub timestamp {
    my ($time) = @_;
    $time = time unless @_ == 1;
    my $HHMMSS   = strftime '%H:%M:%S', gmtime($time);
    return $HHMMSS;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $result = &version_check($required);
#
# DESCRIPTION
#   Checks a version against the current version of SCAR
#   If there is a version mismatch execution if halted
#
# ------------------------------------------------------------------------------

sub version_check {
    my ($caller, $required) = @_;
    die("Version mismatch detected - $caller: $required is less than $VERSION: $VERSION\n")
        if $VERSION > $required;
    return 1;
}

1;

__END__
