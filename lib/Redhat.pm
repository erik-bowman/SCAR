package Redhat;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar qw{
    run_find run_rpm
};
use Scar::File qw{
    read_file get_file_permissions get_file_owner
    get_file_group
};
use Scar::Config;
use Scar::Loader
    require     => 1,
    search_path => ['Redhat::6'],
    sub_name    => 'get_redhat6_plugins';
use Scar::Loader
    require     => 1,
    search_path => ['Redhat::7'],
    sub_name    => 'get_redhat7_plugins';

# Module version
our $VERSION = 0.01;

sub _read_auditd_conf {
    my ($self) = @_;
    my @keywords = qw{
        log_file log_format flush
        freq num_logs max_log_file
        max_log_file_action space_left
        action_mail_acct space_left_action
        admin_space_left admin_space_left_action
        disk_full_action disk_error_action
    };

    my @file_entries = read_file('/etc/audit/auditd.conf');

    foreach my $keyword (@keywords) {

        foreach my $file_entry (@file_entries) {
            chomp $file_entry;
            if ( $file_entry =~ /^($keyword)[= ]{1,3}(.*)$/msx ) {
                push @{ $self->{'/etc/audit/auditd.conf'}->{$1} }, $2;
            }

        }

    }

    return $self->{'/etc/audit/auditd.conf'};
}

sub _read_audisp_syslog_conf {
    my ($self) = @_;
    my @keywords = qw{
        active direction path type args
    };

    my @file_entries = read_file('/etc/audisp/plugins.d/syslog.conf');

    foreach my $keyword (@keywords) {

        foreach my $file_entry (@file_entries) {
            chomp $file_entry;
            if ( $file_entry =~ /^($keyword)[= ]{1,3}(.*)$/msx ) {
                push @{ $self->{'/etc/audisp/plugins.d/syslog.conf'}->{$1} },
                    $2;
            }

        }

    }

    return $self->{'/etc/audisp/plugins.d/syslog.conf'};
}

sub _get_users {
    my ($self) = @_;
    my $entry_counter = 0;
    while (
        my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir,
            $shell ) = getpwent )
    {
        $entry_counter++;
        $self->{users}->{$entry_counter}->{name}    = $name;
        $self->{users}->{$entry_counter}->{passwd}  = $passwd;
        $self->{users}->{$entry_counter}->{uid}     = $uid;
        $self->{users}->{$entry_counter}->{gid}     = $gid;
        $self->{users}->{$entry_counter}->{quota}   = $quota;
        $self->{users}->{$entry_counter}->{comment} = $comment;
        $self->{users}->{$entry_counter}->{gcos}    = $gcos;
        $self->{users}->{$entry_counter}->{dir}     = $dir;
        $self->{users}->{$entry_counter}->{shell}   = $shell;
    }
    return $self->{users};
}

sub _read_yum_config {
    my ($self) = @_;
    my $yum_config = Scar::Config->new();
    $yum_config->open_config_file( '/etc/yum.conf', 'utf8' );
    foreach my $block ( keys %{$yum_config} ) {
        foreach my $keyword ( %{ $yum_config->{$block} } ) {
            $self->{'/etc/yum.conf'}->{$block}->{$keyword}
                = $yum_config->{$block}->{$keyword};
        }
    }
    return $self->{'/etc/yum.conf'};
}

sub _get_lib_permissions {
    my ($self) = @_;
    my @lib_dirs
        = qw{ /lib /lib64 /usr/lib /usr/lib64 /lib /usr/local/lib /usr/local/lib64 };

    foreach my $lib_dir (@lib_dirs) {
        my @dir_contents = run_find("-L $lib_dir -type f");
        foreach my $content (@dir_contents) {
            chomp $content;
            $self->{lib_files}->{$content}->{permissions}
                = get_file_permissions($content);
            $self->{lib_files}->{$content}->{owner}
                = get_file_owner($content);
            $self->{lib_files}->{$content}->{group}
                = get_file_group($content);
        }
    }
    return $self->{lib_files};
}

sub _get_bin_permissions {
    my ($self) = @_;
    my @bin_dirs
        = qw{ /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin };

    foreach my $bin_dir (@bin_dirs) {
        my @dir_contents = run_find("-L $bin_dir -type f");
        foreach my $content (@dir_contents) {
            chomp $content;
            $self->{bin_files}->{$content}->{permissions}
                = get_file_permissions($content);
            $self->{bin_files}->{$content}->{owner}
                = get_file_owner($content);
            $self->{bin_files}->{$content}->{group}
                = get_file_group($content);
        }
    }
    return $self->{bin_files};
}

sub _check_rpm_integrity {
    my ($self) = @_;
    my @failed_integrity_files = run_rpm('-Va');
    foreach my $failed_integrity_file (@failed_integrity_files) {
        chomp $failed_integrity_file;
        my @results = split /\s+/msx, $failed_integrity_file;
        my $result  = shift @results;
        my $file    = pop @results;
        if ( $result
            =~ /^([.S])([.M])([.5])([.D])([.L])([.U])([.G])([.T])/msx )
        {
            $self->{rpm_integrity}->{$file} = {
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
    return $self->{rpm_integrity};
}

1;

__END__
