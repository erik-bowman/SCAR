#!/usr/bin/perl
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

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standardd modules
use FindBin;
use Getopt::Long;
use File::Spec::Functions;

# SCAR Modules
use SCAR;
use SCAR::Log;
use SCAR::RHEL6;
use SCAR::Backup;
use SCAR::Loader;

# Version
our $VERSION = 0.01;

# Start
&start_scar;

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub start_scar {
    my $self = &read_configuration;
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
    my $scar = SCAR->new(
        reports => $self->{directories}->{reports},
        healing => $self->{healing}->{enabled},
    );
    my $log = SCAR::Log->new(
        directory => $self->{directories}->{logs},
        quiet     => $self->{output}->{quiet},
        debug     => $self->{output}->{debug},
    );
    my $RHEL6 = SCAR::RHEL6->new( $self->{directories}->{templates},
        $self->{directories}->{temp} );
    my $backup
        = SCAR::Backup->new( directory => $self->{directories}->{backups}, );
    my $loader
        = SCAR::Loader->new( plugins => $self->{directories}->{plugins}, );

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
        = File::Spec::Functions::catdir( $FindBin::Bin, "config.ini" );
    die "Invalid configuration file specified\n"
        if !-f $configuration_file;

    my $configuration = {};
    my $block         = "_";
    my $counter       = 0;

    open( my $fh, "<:encoding(utf8)", $configuration_file )
        || die "Failed to open file '$configuration_file': $!\n";
    while ( my $line = <$fh> ) {
        $counter++;
        chomp $line;
        next if $line =~ /^\s*(?:\#|\;|$)/;
        $line =~ s/\s\;\s.+$//g;
        if ( $line =~ /^\s*\[\s*(.+?)\s*\]\s*$/ ) {
            $configuration->{ $block = $1 } ||= {};
            next;
        }
        if ( $line =~ /^\s*([^=]+?)\s*=\s*(.*?)\s*$/ ) {
            $configuration->{$block}->{$1} = $2;
            next;
        }
        die "Syntax error at line $counter: '$line'\n";
    }
    close $fh;
    return $configuration;
}

# ------------------------------------------------------------------------------

__END__
