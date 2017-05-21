package Scar::File::Sshd_config;

use strict;
use base qw{ Scar::File };
use warnings FATAL => 'all';

use Carp qw{ croak };
use English qw{ -no_match_vars };

our $VERSION = 0.01;

sub new {
    my ($class) = @ARG;
    my $self = bless {
        Ciphers                 => undef,
        Banner                  => undef,
        Protocol                => undef,
        IgnoreRhosts            => undef,
        PrintLastlog            => undef,
        PermitRootLogin         => undef,
        ClientAliveInterval     => undef,
        ClientAliveCountMax     => undef,
        PermitEmptyPasswords    => undef,
        PermitUserEnvironment   => undef,
        HostbasedAuthentication => undef,
    }, $class;

    my @file_contents;
    open my $file_handle, '<:encoding(utf8)', 'tests/test_data/sshd_config'
        or croak "$OS_ERROR";
    {
        while ( my $line = <$file_handle> ) {
            chomp $line;
            push @file_contents, $line;
        }
    }
    close $file_handle;

    foreach my $line (@file_contents) {
        if ( $line =~ /^Ciphers\s+(.*)$/imsx ) {
            $self->ciphers($1);
        }
        if ( $line =~ /^Banner\s+(.*)$/imsx ) {
            $self->banner($1);
        }
        if ( $line =~ /^Protocol\s+(.*)$/imsx ) {
            $self->protocol($1);
        }
        if ( $line =~ /^IgnoreRhosts\s+(.*)$/imsx ) {
            $self->ignore_rhosts($1);
        }
        if ( $line =~ /^PrintLastlog\s+(.*)$/imsx ) {
            $self->print_last_log($1);
        }
        if ( $line =~ /^PermitRootLogin\s+(.*)$/imsx ) {
            $self->permit_root_login($1);
        }
        if ( $line =~ /^ClientAliveInterval\s+(.*)$/imsx ) {
            $self->client_alive_interval($1);
        }
        if ( $line =~ /^ClientAliveCountMax\s+(.*)$/imsx ) {
            $self->client_alive_count_max($1);
        }
        if ( $line =~ /^PermitEmptyPasswords\s+(.*)$/imsx ) {
            $self->permit_empty_passwords($1);
        }
        if ( $line =~ /^PermitUserEnvironment\s+(.*)$/imsx ) {
            $self->permit_user_environment($1);
        }
        if ( $line =~ /^HostbasedAuthentication\s+(.*)$/imsx ) {
            $self->hostbased_authentication($1);
        }

    }

    return $self;
}

sub ciphers {
    my ( $self, @values ) = @ARG;
    if ( @ARG == 2 ) {
        foreach my $value (@values) {
            push @{ $self->{Ciphers} }, $value;
        }
    }
    return $self->{Ciphers};
}

sub banner {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{Banner} = $value;
    }
    return $self->{Banner};
}

sub protocol {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{Protocol} = $value;
    }
    return $self->{Protocol};
}

sub ignore_rhosts {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{IgnoreRhosts} = $value;
    }
    return $self->{IgnoreRhosts};
}

sub print_last_log {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PrintLastlog} = $value;
    }
    return $self->{PrintLastlog};
}

sub permit_root_login {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitRootLogin} = $value;
    }
    return $self->{PermitRootLogin};
}

sub client_alive_interval {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{ClientAliveInterval} = $value;
    }
    return $self->{ClientAliveInterval};
}

sub client_alive_count_max {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{ClientAliveCountMax} = $value;
    }
    return $self->{ClientAliveCountMax};
}

sub permit_empty_passwords {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitEmptyPasswords} = $value;
    }
    return $self->{PermitEmptyPasswords};
}

sub permit_user_environment {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitUserEnvironment} = $value;
    }
    return $self->{PermitUserEnvironment};
}

sub hostbased_authentication {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{HostbasedAuthentication} = $value;
    }
    return $self->{HostbasedAuthentication};
}

1;

__END__
