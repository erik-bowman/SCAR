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
use lib "$FindBin::Bin/../lib";
use File::Spec::Functions;
use warnings FATAL => 'all';

# Scar Modules
use Scar::Util::Log;
use Scar::Util::Backup;
use Scar qw ( IMPLODEPATH );
use Redhat::6;

# Version
our $VERSION = 0.01;

my @PLUGINS;
my $RHEL6  = Redhat::6->new();

# Start
start_scar();

sub start_scar {
    my $self = {};
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

    foreach my $PLUGIN ( $RHEL6->get_redhat6_plugins() ) {
        my $LOADEDPLUGIN = $PLUGIN->new($RHEL6);

        if ( !$LOADEDPLUGIN->can('check') ) {
            next;
        }

        print "Starting " . $LOADEDPLUGIN->STIG_ID() . "\n";
        $LOADEDPLUGIN->check();
        if (defined $LOADEDPLUGIN->{STATUS}) {
            print "$LOADEDPLUGIN->{STATUS}\n";
        }
    }

#        if ( $LOADEDPLUGIN->{STATUS} eq 'O' ) {
#
#            if ( !$LOADEDPLUGIN->can('remediate') ) {
#                next;
#            }
#
#            push @PLUGINS, $LOADEDPLUGIN;
#        }
#
#    }

    return 1;
}

#sub run_remediations {
#
#    foreach my $PLUGIN (@PLUGINS) {
#        $PLUGIN->remediate();
#    }
#
#    run_checks();
#    return 1;
#}


__END__
