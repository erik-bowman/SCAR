#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::RHEL
#
# DESCRIPTION
#   Performs SCAR initialization tasks specific to Red Hat
#
# SEE ALSO
#   SCAR SCAR::RHEL6 SCAR::RHEL7
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::RHEL;

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
#   $result = SCAR::RHEL->new(%args);
#
# DESCRIPTION
#
# ARGUMENTS
#   $class, %argrs
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $conf, $log, $backup ) = @_;
    SCAR->version_check($class, $VERSION);
    my $self = bless {
        conf   => Config::Tiny->read($conf),
        log    => $log,
        backup => $backup,
    }, $class;
    $self->search_path( new => $self->{conf}->{directories}->{plugins} );
    $self->{log}->info("$class: Initialized");
    sleep 1;
    return $self;
}

1;

__END__
