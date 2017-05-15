#!/usr/bin/perl
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

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# SCAR modules
use Config::Tiny;
use Module::Pluggable inner => 0;

# Module version
our $VERSION   = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $result = SCAR::RHEL6->new(%args);
#
# DESCRIPTION
#
# ARGUMENTS
#   %args
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $conf, $log, $backup ) = @_;
    SCAR->version_check($class, $VERSION);
    my $self = bless { conf => Config::Tiny->read($conf), log => $log, backup => $backup}, $class;
    $self->search_( new => $self->{conf}->{directories}->{plugins} );

    return $self;
}

1;

__END__
