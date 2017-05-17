#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Backup
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

package SCAR::Backup;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;

# Module version
our $VERSION = 0.01;

# Active backup directory
our $DIRECTORY;

# Default exports
our @EXPORT = qw( BACKUP );

# ------------------------------------------------------------------------------
# SYNOPSIS
#   BACKUP
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub BACKUP {
    my ($SOURCEFILE) = @_;
    my @PATHINFO = EXPLODEPATH($SOURCEFILE);
    my $BACKUPFILE = IMPLODEPATH( $DIRECTORY, $PATHINFO[2] );
    if ( !-f $BACKUPFILE ) {
        open my $INPUT,  '<:raw', $SOURCEFILE or croak;
        open my $OUTPUT, '>:raw', $BACKUPFILE or croak;
        while (<$INPUT>) {
            print {$OUTPUT} $_;
        }
        close $INPUT;
        close $OUTPUT;
    }
    return 1;
}

# ------------------------------------------------------------------------------

1;

__END__
