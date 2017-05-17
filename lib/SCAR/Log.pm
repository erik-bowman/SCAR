#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Log
#
# DESCRIPTION
#
#
# SEE ALSO
#   SCAR
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Log;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use warnings FATAL => 'all';

# SCAR modules
use SCAR;

# Module version
our $VERSION = 0.01;

# Active log directory
our $DIRECTORY;

# Default exports
our @EXPORT = qw( INFO WARN ERROR DEBUG );

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub ERROR {
    my ($message) = @_;
    write_to_file( 'error.log', $message );
    print HHMMSS() . " ERROR: $message";
    croak;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub INFO {
    my ($message) = @_;
    write_to_file( 'scar.log', $message );
    print HHMMSS() . "  INFO: $message";
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub WARN {
    my ($message) = @_;
    write_to_file( 'scar.log', "Warning: $message" );
    print HHMMSS() . "  WARN: $message";
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub DEBUG {
    my ($message) = @_;
    write_to_file( 'debug.log', $message );
    print HHMMSS() . " DEBUG: $message";
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   write_to_file
#
# DESCRIPTION
#   Writes an entry into the specified log file
#
# ARGUMENTS
#   $file       - the log file for writing to
#   $message    - the entry for the log file
#
# ------------------------------------------------------------------------------

sub write_to_file {
    my ( $file, $message ) = @_;
    if ( !-d $DIRECTORY ) { croak 'No output directory defined' }
    open my $fh, '>>:encoding(utf8)', IMPLODEPATH( $DIRECTORY, $file )
        or croak;
    print {$fh} HHMMSS() . ": $message\n";
    close $fh;
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub hhmmss {
    return POSIX::strftime '%H:%M:%S', gmtime();
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub yyyymmdd {
    return POSIX::strftime '%Y-%m-%d', gmtime();
}

# ------------------------------------------------------------------------------

1;

__END__
