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
use Scar;
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
        'test-check=s'   => \$self->{test_check},
        'test-heal=s'    => \$self->{test_heal},
    );

    run_checks($self);
#    run_remediations();

    return 1;
}

sub run_checks {
    my ($self) = @_;
    foreach my $plugin ( $RHEL6->get_redhat6_plugins() ) {

        if (defined $self->{test_check}) {
            if ($plugin->get_stig_id ne $self->{test_check}) {
                next;
            }
        }
        my $initialized_plugin = $plugin->new($RHEL6);
        if ( !$initialized_plugin->can('check') ) {
            next;
        }
        print "Starting " . $initialized_plugin->get_stig_id() . "\n";
        $initialized_plugin->check();
        if (defined $initialized_plugin->get_finding_status()) {
            print $initialized_plugin->get_finding_status()."\n";
        }
    }

    return 1;
}


__END__
