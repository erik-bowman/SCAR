#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::RHEL6
#
# DESCRIPTION
#   Performs SCAR initialization tasks specific to Red Hat 6
#
# SEE ALSO
#   SCAR SCAR::RHEL
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::RHEL6;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;

# Module version
our $VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   new
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;

    return $self;
}

# ------------------------------------------------------------------------------

1;

__END__
