#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR
#
# DESCRIPTION
#   Performs SCAR initialization tasks
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

package SCAR;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use POSIX;
use File::Spec::Functions;

# Module version
our $VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class ) = @_;
    my $self = bless {}, $class;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   check_failed
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub check_failed {
    my ( $self, $severity ) = @_;
    $self->{$severity}->{not_a_finding}++;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   check_passed
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub check_passed {
    my ( $self, $severity ) = @_;
    $self->{$severity}->{open_findings}++;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   attempting_remediation
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub remediation_attempted {
    my ($self) = @_;
    $self->{remediation}->{attempted}++;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   remediation_failed
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub remediation_failed {
    my ($self) = @_;
    $self->{remediation}->{failed}++;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   remediation_success
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub remediation_success {
    my ($self) = @_;
    $self->{remediation}->{success}++;
}

# ------------------------------------------------------------------------------

1;

__END__
