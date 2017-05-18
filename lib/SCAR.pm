#!/bin/env perl

package SCAR;

# Standard modules
use utf8;
use 5.008;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use POSIX qw( strftime );
use File::Spec::Functions;
use warnings FATAL => 'all';

# Module version
our $VERSION = 0.01;

# Default exports
our @EXPORT = qw( AWK GREP PARSE IMPLODEPATH EXPLODEPATH HHMMSS YYYYMMDD );

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub IMPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::catdir(@PARTS);
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub EXPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::splitpath(@PARTS);
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub HHMMSS {
    return strftime '%H:%M:%S', gmtime;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub YYYYMMDD {
    return strftime '%Y-%m-%d', gmtime;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub AWK {
    my ($CODE, $FILE) = @_;
    my @RESULTS;
    open my $AWK, " /bin/awk '$CODE' $FILE 2>&1 |" or croak 'Could not run awk';
    {
        while (my $RESULT = <$AWK>) {
            push @RESULTS, $RESULT;
        }
    }
    close $AWK;
    return @RESULTS;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   PARSE
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub PARSE {
    my ( $FILE, $REGEX ) = @_;
    my @RESULTS;
    open my $FH, '<:encoding(utf8)', $FILE or croak 'Could not parse file';
    {
        while (my $LINE = <$FH>) {
            if ($LINE =~ /$REGEX/msx) {
                push @RESULTS, $&;
            }
        }
    }
    close $FH;
    return @RESULTS;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   SYSGREP
#
# DESCRIPTION
#
# ARGUMENTS
#   $EXPRESSION         - A grep expression
#
# ------------------------------------------------------------------------------

sub GREP {
    my ($PATTERN, $PATH) = @_;
    my @RESULTS;
    open my $GREP, " /bin/grep $PATTERN $PATH 2>&1 |" or croak 'Could not run grep';
    {
        while (my $RESULT = <$GREP>) {
            push @RESULTS, $RESULT;
        }
    }
    close $GREP;
    return @RESULTS;
}

1;
=pod

=head1 NAME

SCAR - Exports core methods used throughout the package.


=head1 VERSION

This docuemntation refers to SCAR version 1.4.0


=head1 SYNOPSIS

    use SCAR;

    $PATH       = IMPLODEPATH( @COMPONENTS );
    @COMPONENTS = EXPLODEPATH( $PATH );
    $DATESTRING = YYYYMMDD();
    $TIMESTRING = HHMMSS();


=head1 DESCRIPTION

This is the core module for Security Compliance and Remediation aka SCAR.
Exports methods used ubiquitously throughout SCAR by default;


=head1 SUBROUTINES/METHODS


=head1 DIAGNOSTICS


=head1 CONFIGURATION AND ENVIRONMENT


=head1 DEPENDENCIES

Perl 5.008, Exporter

=head1 INCOMPATIBILITIES


=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.
Please report problems to Erk Bowman (erik.bowman@icsinc.com)
Patches are welcome.


=head1 AUTHOR

Erik Bowman (erik.bowman@icsinc.com)


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2017 Erik Bowman (erik.bowman@icsinc.com). All rights reserved.

This module is private software; do not redistribute it and/or
modify it without proper authorization or approval.

This program is distributed in the hopes that it wil be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


=cut

__END__
