#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::RHEL7
#
# DESCRIPTION
#   Performs SCAR initialization tasks specific to Red Hat 7
#
# SEE ALSO
#   SCAR SCAR::RHEL
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::RHEL7;

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
#   $result = SCAR::RHEL7->new(%args);
#
# DESCRIPTION
#
# ARGUMENTS
#   %args
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
