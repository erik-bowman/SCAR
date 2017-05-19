package Scar;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use Carp qw( croak );
use base qw( Exporter );
use POSIX qw( strftime );
use File::Spec::Functions;

# Module version
our $VERSION = 0.01;

# Exportables
our @EXPORT_OK
    = qw( run_awk run_grep parse_file run_service run_chkconfig implode_path explode_path get_strftime get_strfdate );

sub implode_path {
    my @path_components = @_;
    return File::Spec::Functions::catdir(@path_components);
}

sub explode_path {
    my @directories = @_;
    return File::Spec::Functions::splitpath(@directories);
}

sub get_strftime {
    return strftime '%H:%M:%S', gmtime;
}

sub get_strfdate {
    return strftime '%Y-%m-%d', gmtime;
}

sub _run_system_bin {
    my ( $bin, $args ) = @_;
    my @results;

    open my $bin_handler, q<|->, qq|$bin $args 2>&1|
        or croak "Could not run $bin\n";
    {
        while ( my $response_line = <$bin_handler> ) {
            push @results, $response_line;
        }
    }
    close $bin_handler;

    return @results;
}

sub run_awk {
    my ($args) = @_;
    return _run_system_bin( '/bin/awk', $args );
}

sub run_grep {
    my ($args) = @_;
    return join "\n", _run_system_bin( '/bin/grep', $args );
}

sub run_service {
    my ($args) = @_;
    return join "\n", _run_system_bin( '/sbin/service', $args );
}

sub run_chkconfig {
    my ($args) = @_;
    return _run_system_bin( '/sbin/chkconfig', $args );
}

sub parse_file {
    my ( $regex, $file ) = @_;
    my @results;

    open my $file_hanlder, '<:encoding(utf8)', $file
        or croak 'Could not parse file';
    {
        while ( my $line_in_file = <$file_hanlder> ) {
            if ( $line_in_file =~ /$regex/msx ) {
                push @results, $line_in_file;
            }
        }
    }
    close $file_hanlder;

    return @results;
}

1;

__END__

=pod

=head1 NAME


=head1 VERSION


=head1 SYNOPSIS


=head1 DESCRIPTION


=head1 OPTIONS


=head1 REQUIRED ARGUMENTS


=head1 SUBROUTINES/METHODS


=head1 DIAGNOSTICS


=head1 EXIT STATUS


=head1 CONFIGURATION AND ENVIRONMENT


=head1 DEPENDENCIES


=head1 INCOMPATIBILITIES


=head1 BUGS AND LIMITATIONS


=head1 AUTHOR


=head1 LICENSE AND COPYRIGHT


=cut
