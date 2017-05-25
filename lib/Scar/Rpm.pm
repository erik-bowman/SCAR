package Scar::Rpm;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::Commands;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    my @failed_integrity_files = run_rpm('-Va');
    foreach my $failed_integrity_file (@failed_integrity_files) {
        chomp $failed_integrity_file;
        my @results = split /\s+/msx, $failed_integrity_file;
        my $result  = shift @results;
        my $file    = pop @results;
        if ( $result
            =~ /^([.S])([.M])([.5])([.D])([.L])([.U])([.G])([.T])/msx )
        {
            $self->{$file} = {
                size    => $1 eq 'S' ? 'fail' : 'pass',
                mode    => $2 eq 'M' ? 'fail' : 'pass',
                md5sum  => $3 eq '5' ? 'fail' : 'pass',
                version => $4 eq 'D' ? 'fail' : 'pass',
                link    => $5 eq 'L' ? 'fail' : 'pass',
                owner   => $6 eq 'U' ? 'fail' : 'pass',
                group   => $7 eq 'G' ? 'fail' : 'pass',
                mtime   => $8 eq 'T' ? 'fail' : 'pass',
            };
        }
    }
    return $self;
}

1;
