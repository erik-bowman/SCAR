#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   Backup
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

package Backup;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;

# ------------------------------------------------------------------------------

my $VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ($class, $base_directory) = @_;
    SCAR->version_check($class, $VERSION);
    my @timestamp = &timestamp();
    my $self = bless {
            base => "$base_directory",
            active => "$base_directory/$timestamp[0]",
        }, $class;

    return $self;
}

# ------------------------------------------------------------------------------

1;

__END__
