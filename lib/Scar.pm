package Scar;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use Fcntl;
use Carp qw{ croak };
use base qw{ Exporter };
use POSIX qw{ strftime };
use English qw{ -no_match_vars };
use File::Spec::Functions;

# Module version
our $VERSION = 0.01;

# Exportables
our @EXPORT_OK = qw{
    run_awk run_grep run_service run_chkconfig run_find run_rpm
    implode_path explode_path make_path_absolute
    get_strftime get_strfdate read_file
    get_current_directory
    get_file_owner get_file_group get_file_permissions
};

sub implode_path {
    my @path_components = @_;
    return File::Spec::Functions::catdir(@path_components);
}

sub explode_path {
    my @directories = @_;
    return File::Spec::Functions::splitpath(@directories);
}

sub make_path_absolute {
    my ( $file, $base ) = @_;
    return File::Spec::Functions::abs2rel( $file, $base );
}

sub get_current_directory {
    return File::Spec::Functions::curdir();
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

    open my $bin_handler, q{-|}, qq{$bin $args 2>&1}
        or croak "Could not run '$bin': $OS_ERROR\n";
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

sub run_find {
    my ($args) = @_;
    return _run_system_bin( '/bin/find', $args );
}

sub run_rpm {
    my ($args) = @_;
    return _run_system_bin( '/bin/rpm', $args );
}

sub read_file {
    my ($file) = @_;
    my @results;

    open my $file_hanlder, '<:encoding(utf8)', $file
        or croak "Could not parse file '$file': $OS_ERROR";
    {
        while ( my $line_in_file = <$file_hanlder> ) {
            chomp $line_in_file;
            push @results, $line_in_file;
        }
    }
    close $file_hanlder;

    return @results;
}

sub get_file_owner {
    my ($file) = @_;
    if ( !-f $file ) {
        croak
            "Unable to get the owner uid for file '$file': file does not exist";
    }
    return ( stat $file )[4];
}

sub get_file_group {
    my ($file) = @_;
    if ( !-f $file ) {
        croak
            "Unable to get the owner gid for file '$file': file does not exist";
    }
    return ( stat $file )[5];
}

sub get_file_permissions {
    my ($file) = @_;
    if ( !-f $file ) {
        croak
            "Unable to get permissions for file '$file': file does not exist";
    }
    my $file_permissions = ( stat $file )[2];
    return sprintf '%04o', Fcntl::S_IMODE($file_permissions);
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
