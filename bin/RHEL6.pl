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
use SCAR qw ( IMPLODEPATH );
use SCAR::Log;
use SCAR::RHEL6;
use SCAR::Backup;
use SCAR::Loader;

# Version
our $VERSION = 0.01;

my @PLUGINS;
$main::RHEL6  = SCAR::RHEL6->new();
$main::LOADER = SCAR::Loader->new();

# Start
start_scar();

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

    run_checks();
    run_remediations();

    return 1;
}

sub run_checks {

    foreach my $PLUGIN ( $main::LOADER->PLUGINS() ) {
        my $LOADEDPLUGIN = $PLUGIN->new($main::RHEL6);

        if ( !$LOADEDPLUGIN->can('check') ) {
            next;
        }

        $LOADEDPLUGIN->check();

        if ( $LOADEDPLUGIN->{STATUS} eq 'O' ) {

            if ( !$LOADEDPLUGIN->can('remediate') ) {
                next;
            }

            push @PLUGINS, $LOADEDPLUGIN;
        }

    }

    return 1;
}

sub run_remediations {

    foreach my $PLUGIN (@PLUGINS) {
        $PLUGIN->remediate();
    }

    run_checks();
    return 1;
}

sub read_configuration {
    my $CONFIGFILE = IMPLODEPATH( $FindBin::Bin, 'config.ini' );
    if ( !-f $CONFIGFILE ) { croak 'Invalid configuration file specified'; }
    my @CONTENTS;

    open my $FH, '<:encoding(utf8)', $CONFIGFILE
        or croak 'Failed to open file';
    {
        while ( my $LINE = <$FH> ) {
            push @CONTENTS, $LINE;
        }
    }
    close $FH;

    return parse_config();
}

sub parse_config {
    my (@CONTENTS) = @_;
    my $CONFIG     = {};
    my $SECTION    = '_';

    foreach my $LINE (@CONTENTS) {
        chomp $LINE;

        if ( $LINE =~ /^\s*(?:[\#|\;]|$)/msx ) {
            next;
        }

        $LINE =~ s/\s\;\s.+$//msxg;

        if ( $LINE =~ /^\s*\[\s*(.+?)\s*\]\s*$/msx ) {
            $CONFIG->{ $SECTION = $1 } ||= {};
            next;
        }

        if ( $LINE =~ /^\s*([^=]+?)\s*=\s*(.*?)\s*$/msx ) {
            $CONFIG->{$SECTION}->{$1} = $2;
            next;
        }

        croak 'Syntax error';
    }

    return $CONFIG;
}

__END__
