#!/usr/bin/perl
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

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# SCAR modules
use Config::Tiny;
use Module::Pluggable inner => 0;

# ------------------------------------------------------------------------------

my $VERSION   = 0.01;

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
    my ( $class, $conf, $log, $backup ) = @_;
    SCAR->version_check($class, $VERSION);
    my $self = bless { conf => Config::Tiny->read($conf), log => $log, backup => $backup}, $class;
    $self->search_path( new => $self->{conf}->{directories}->{plugins} );
    $self->{log}->info("$class: Initialized");
    sleep 1;
    return $self;
}

1;

__END__
