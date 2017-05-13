#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR
#
# DESCRIPTION
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

package SCAR;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use POSIX qw(uname);
use File::Path qw(make_path);

# Development modules
use Data::Dumper;

# ------------------------------------------------------------------------------

BEGIN {
    # Exports
    use Exporter;

    # Globals
    use vars
        qw($VERSION @ISA @EXPORT @EXPORT_OK @DIRECTORIES);

    $VERSION        = 0.01;
    @ISA            = qw(Exporter);
    @EXPORT         = qw(initialize);
    @EXPORT_OK      = qw();
    @DIRECTORIES    = qw(
        /SCAR
        /SCAR/tmp
        /SCAR/logs
        /SCAR/backups
        );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub initialize {
    my (%args) = @_;
    my $self = \%args;
    (   $self->{uname}->{sysname}, $self->{uname}->{nodename},
        $self->{uname}->{release}, $self->{uname}->{version},
        $self->{uname}->{machine}
    ) = POSIX::uname();

    unless ( check_directories() ) {
        make_directories();
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

sub check_directories {
    foreach my $directory (@DIRECTORIES) {
        unless ( -d $directory ) {
            return 0;
        }
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

sub make_directories {
    foreach my $directory (@DIRECTORIES) {
        unless ( -d $directory ) {
            make_path($directory);
        }
    }
    return 1;
}

# ------------------------------------------------------------------------------

1;

__END__
