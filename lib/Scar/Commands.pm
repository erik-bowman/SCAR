package Scar::Commands;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_match_vars };

# Modules Hierarchy
use base qw{ Exporter };

# Module Version
our $VERSION = 1.40;

# Module Exports
our @EXPORT = qw{
    run_awk _run_system_bin run_grep run_service run_chkconfig run_modprobe run_find run_rpm
};

sub _run_system_bin {
    my ( $bin, $args ) = @ARG;
    my @results;

    open my $bin_handler, q{-|}, qq{$bin $args 2>&1}
        or croak "Could not run '$bin': $OS_ERROR\n";
    {
        while ( my $response_line = <$bin_handler> ) {
            chomp $response_line;
            push @results, $response_line;
        }
    }
    close $bin_handler;

    return @results;
}

sub run_awk {
    my ($args) = @ARG;
    return _run_system_bin( '/bin/awk', $args );
}

sub run_grep {
    my ($args) = @ARG;
    return join "\n", _run_system_bin( '/bin/grep', $args );
}

sub run_service {
    my ($args) = @ARG;
    return join "\n", _run_system_bin( '/sbin/service', $args );
}

sub run_chkconfig {
    my ($args) = @ARG;
    return _run_system_bin( '/sbin/chkconfig', $args );
}

sub run_modprobe {
    my ($args) = @ARG;
    return _run_system_bin( '/sbin/modprobe', $args );
}

sub run_find {
    my ($args) = @ARG;
    return _run_system_bin( '/bin/find', $args );
}

sub run_rpm {
    my ($args) = @ARG;
    return _run_system_bin( '/bin/rpm', $args );
}

1;
