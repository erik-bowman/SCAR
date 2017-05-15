#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::RHEL
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

package SCAR::RHEL;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Module version
our $VERSION   = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $result = SCAR::RHEL->new(%args);
#
# DESCRIPTION
#
# ARGUMENTS
#   $class, %argrs
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, %args ) = @_;
    my $self = bless \%args, $class;

    open( SYSTEM, "getconf LONG_BIT 2>&1 |") || die "can't fork: $!";
    {
        $self->{ARCH} = $_;
    }
    close SYSTEM || die "Bad command: $! $?";

    print "$self->{ARCH}\n";

    return $self;
}

# ------------------------------------------------------------------------------

1;

__END__
