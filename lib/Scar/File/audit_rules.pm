package Scar::Files::audit_rules;

# Standard pragmas
use strict;
use base qw{ Redhat::Audit };
use warnings FATAL => 'all';

# Standard modules
use Getopt::Long;

# Development only modules
use Data::Dumper;

# Scar modules
use Scar qw{ run_find };

sub new {
    my ($class) = @_;
    my $self = bless { }, $class;
    return $self;
}



sub _sort_files_naturally {
    my ( $numeric, $alpha ) = @_;
    $item = 0;
    $i = 1;

    while ( $i < @{$numeric} and $i < @{$alpha} ) {
        last if $item = ( $numeric->[$i] cmp $alpha->[$i] );
        ++$i;

        last if $item = ( $numeric->[$i] <=> $alpha->[$i] );
        ++$i;
    }

    return
        $item
            || ( @{$numeric} <=> @{$alpha} )
            || ( $numeric->[0] cmp $alpha->[0] );
}

sub _file_iterator {
    ($item) = @_;
    if (!defined $item) {
        $item = q{};
    }
    my @fields = ($item);

    if ($item
        =~ m/^[+-]?(?=\d|[.]\d)\d*(?:[.]\d*)?(?:[Ee](?:[+-]?\d+))?\z/msx)
    {
        push @fields, q{}, $item;
    }
    else {
        while ( length $item ) {

            if ($item =~ s/^(\D+)//msx) {
                push @fields, lc $1;
            }
            else {
                push @fields, qw{};
            }

            if ($item =~ s/^(\d+)//msx) {
                push @fields, $1;
            }
            else {
                push @fields, 0;
            }

        }
    }
    return \@fields;
}

sub _set_boolean {
    my ($self, $boolean) = @_;
    if ($boolean eq '-D') {
        if ($self->{rules}[0] eq '-D') {
            push @{ $self->{errors} }, 'Duplicate entries detected: -D specified twice';
        }
        else {
            $self->{rules}[0] = $boolean;
        }
    }
    return;
}

sub _set_property {
    my ($self, $property, $value) = @_;
    if ($property eq '-b' && defined $value) {
        if ($self->{rules}[1] =~ /^-b/msx) {
            push @{ $self->{errors} }, 'Duplicate entries detected: -b specified twice';
        }
        else {
            $self->{rules}[1] = "$property $value";
        }
    }
    return;
}

1;

 __END__
