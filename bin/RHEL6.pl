#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#
#
# SYNOPSIS
#
#
# DESCRIPTION
#
#
# OPTIONS
#
#
# ARGUMENTS
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

# Standard modules
use utf8;
use strict;
use FindBin;
use Getopt::Long;
use Carp qw( croak );
use File::Spec::Functions;
use warnings FATAL => 'all';

# SCAR Modules
use SCAR;
use SCAR::Log;
use SCAR::RHEL6;
use SCAR::Backup;
use SCAR::Loader;

# Version
our $VERSION = 0.01;

# Start
start_scar();

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub start_scar {
    my $self = read_configuration();
    Getopt::Long::GetOptions(
        'base=s'         => \$self->{directories}->{base},
        'logs=s'         => \$self->{directories}->{logs},
        'backups=s'      => \$self->{directories}->{backups},
        'reports=s'      => \$self->{directories}->{reports},
        'plugins=s'      => \$self->{directories}->{plugins},
        'templates=s'    => \$self->{directories}->{templates},
        'enable-healing' => \$self->{healing}->{enabled},
        'debug|d'        => \$self->{output}->{debug},
        'quiet|q'        => \$self->{output}->{quiet},
    );
    $main::SCAR = SCAR->new();
    $main::RHEL6 = SCAR::RHEL6->new();
    $main::LOADER = SCAR::Loader->new();

    my @remediations;
    foreach my $plugin ( $loader->load_plugins ) {
        my $obj = $plugin->new( $scar, $log, $backup, $RHEL6 );
        next unless $obj->can("check");
        if ( $obj->check eq "O" && $obj->can("remediate") ) {
            push @remediations, $obj;
        }
    }

    foreach my $plugin (@remediations) {
        $plugin->remediate();
    }
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub read_configuration {
    my $configuration_file
        = File::Spec::Functions::catdir( $FindBin::Bin, 'config.ini' );
    croak 'Invalid configuration file specified'
        if !-f $configuration_file;

    my $configuration = {};
    my $block         = '_';

    open my $fh, '<:encoding(utf8)', $configuration_file or croak 'Failed to open file';
    while ( my $line = <$fh> ) {
        chomp $line;
        next if $line =~ /^\s*(?:[\#|\;]|$)/msx;
        $line =~ s/\s\;\s.+$//g;
        if ( $line =~ /^\s*\[\s*(.+?)\s*\]\s*$/msx ) {
            $configuration->{ $block = $1 } ||= {};
            next;
        }
        if ( $line =~ /^\s*([^=]+?)\s*=\s*(.*?)\s*$/msx ) {
            $configuration->{$block}->{$1} = $2;
            next;
        }
        croak 'Syntax error';
    }
    close $fh;
    return $configuration;
}

# ------------------------------------------------------------------------------

__END__
