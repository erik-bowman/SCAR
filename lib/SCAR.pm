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
use 5.010;
use strict;
use warnings FATAL => 'all';

# Standard modules
use Time::HiRes qw( sleep );

# SCAR modules
use SCAR::Log;
use SCAR::RHEL;
use SCAR::RHEL6;
use SCAR::RHEL7;
use SCAR::Backup;
use Config::Tiny;
use Module::Pluggable inner => 0;

# Development modules
#use Data::Dumper;

# ------------------------------------------------------------------------------

my $VERSION   = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $conf, $debug, $quiet ) = @_;
    my $self = bless { conf => Config::Tiny->read($conf), }, $class;
    $self->search_path( new => $self->{directories}->{plugins} );
    my $SOCK_PATH = "$self->{conf}->{directories}->{temp}/scar.sock";
    unlink if -d $SOCK_PATH;
    my $pid = fork();
    die ("Failed to SCAR.\n") unless defined $pid;
    if ($pid) {
        SCAR::Console->new($SOCK_PATH);
    } else {
        $self->init_log($SOCK_PATH, $debug);
        $self->init_backup();
        $self->init_os();
        exit 0;
    }
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub init_os {
    my ($self) = @_;
    my $mainconf = File::Spec->catdir(
            $self->{conf}->{directories}->{conf},
            "/$self->{conf}->{os}->{type}.conf"
    );
    my $subconf = File::Spec->catdir(
            $self->{conf}->{directories}->{conf},
            "/$self->{conf}->{os}->{type}$self->{conf}->{os}->{version}.conf"
    );
    $self->{os}->{main} = SCAR::RHEL->new($mainconf, $self->{log}, $self->{backup})
        if $self->{conf}->{os}->{type} eq 'RHEL';
    $self->{os}->{sub} = SCAR::RHEL6->new($subconf, $self->{log}, $self->{backup})
        if $self->{conf}->{os}->{version} eq '6';
    $self->{os}->{sub} = SCAR::RHEL7->new($subconf, $self->{log}, $self->{backup})
        if $self->{conf}->{os}->{version} eq '7';
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub init_log {
    my ($self, $sock_path, $debug, $quiet) = @_;
    $self->{log} = SCAR::Log->new( $self->{conf}->{directories}->{logs}, $sock_path, $debug );
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub init_backup {
    my ($self) = @_;
    $self->{backup}
        = SCAR::Log->new( $self->{conf}->{directories}->{backups} );
    return $self;
}

# ------------------------------------------------------------------------------

1;

__END__
