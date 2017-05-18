#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL6_plugin_generator.pl
#
# SYNOPSIS
#   RHEL6_plugin_generator.pl [options] args
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
#
# ------------------------------------------------------------------------------

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use FindBin;
use File::Spec::Functions;

# Vesion
our $VERSION = 0.01;

my $VULNID       = qr/^"(V-\d+)",/msx;
my $SEVERITY     = qr/"(high|medium|low)",/msx;
my $GROUPTITLE   = qr/"(SRG-OS-\d+|GEN\d+|RHEL-06-000293)",/msx;
my $RULEID       = qr/"(SV-\w+)",/msx;
my $STIGID       = qr/"(RHEL-06-\d+)",/msx;
my $RULETITLE    = qr/"(.*?)",/msx;
my $DISCUSSION   = qr/"((?:\"\")*|.*?)","",/msx;
my $CHECKCONTENT = qr/"((?:\"\")*|.*?)",/msx;
my $FIXCONTENT   = qr/"((?:\"\")*|.*?)",/msx;
my $FILLER = qr/"","","false","","","","","","","","Unclass",".*?","\d+",/msx;
my $CCI    = qr/"(.*?)",\n/msx;
my $REGEX
    = $VULNID
    . $SEVERITY
    . $GROUPTITLE
    . $RULEID
    . $STIGID
    . $RULETITLE
    . $DISCUSSION
    . $CHECKCONTENT
    . $FIXCONTENT
    . $FILLER
    . $CCI;

my $CSVFILE = File::Spec::Functions::catdir( $FindBin::Bin,
    qw(.. stigs U_RedHat_6_STIG_V1R15.csv) );

my @CONTENTS;

open my $CSVH, '<:encoding(utf8)', $CSVFILE;
{
    @CONTENTS = <$CSVH>;
}
close $CSVH;

my $CONTENT = join "\n", @CONTENTS;

while ( $CONTENT =~ /$REGEX/msxg ) {
    my @PACKAGENAME = split qr/-/msx, $5;
    my $TEMPLATE = <<"TEMPLATE";
#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]
#
# VULN ID
#   $1
#
# SEVERITY
#   $2
#
# GROUP TITLE
#   $3
#
# RULE ID
#   $4
#
# STIG ID
#   $5
#
# RULE TITLE
#   $6
#
# AUTHOR
#   Erik Bowman (erik.bowman\@icsinc.com)
#
# ------------------------------------------------------------------------------

package $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2];

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Plugin version
our \$VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$plugin = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->new(\$core, \$log, \$backup, \$parent);
#
# DESCRIPTION
#   Initializes the plugin object and returns it
#
# ARGUMENTS
#   \$core      = The Scar module object
#   \$log       = The Scar::Log module object
#   \$backup    = The Scar::Backup module object
#   \$parent    = The Scar::RHEL6 module object
#
# ------------------------------------------------------------------------------

sub new {
    my ( \$class, \$core, \$log, \$backup, \$parent ) = \@_;
    my \$self = bless {
        core   => \$core,
        log    => \$log,
        backup => \$backup,
        parent => \$parent,
    }, \$class;

    return \$self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$results = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->check();
#
# DESCRIPTION
#   Performs a test against the system
#
# ------------------------------------------------------------------------------

sub check {
    my (\$self) = \@_;

    return \$self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$results = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->remediate();
#
# DESCRIPTION
#   Attempts remediation
#
# ------------------------------------------------------------------------------

sub remediate {
    my (\$self) = \@_;

    return \$self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$VULN_ID = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->VULN_ID();
#
# DESCRIPTION
#   Returns the plugins VULN ID
#
# ------------------------------------------------------------------------------

sub VULN_ID {
    my (\$self) = \@_;
    \$self->{VULN_ID}  = '$1';
    return \$self->{VULN_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$SEVERITY = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->SEVERITY();
#
# DESCRIPTION
#   Returns the plugins SEVERITY
#
# ------------------------------------------------------------------------------

sub SEVERITY {
    my (\$self) = \@_;
    \$self->{SEVERITY} = '$2';
    return \$self->{SEVERITY};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$GROUP_TITLE = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->GROUP_TITLE();
#
# DESCRIPTION
#   Returns the plugins GROUP TITLE
#
# ------------------------------------------------------------------------------

sub GROUP_TITLE {
    my (\$self) = \@_;
    \$self->{GROUP_TITLE} = '$3';
    return \$self->{GROUP_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$RULE_ID = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->RULE_ID();
#
# DESCRIPTION
#   Returns the plugins RULE ID
#
# ------------------------------------------------------------------------------

sub RULE_ID {
    my (\$self) = \@_;
    \$self->{RULE_ID}  = '$4';
    return \$self->{RULE_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$STIG_ID = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->STIG_ID();
#
# DESCRIPTION
#   Returns the plugins STIG ID
#
# ------------------------------------------------------------------------------

sub STIG_ID {
    my (\$self) = \@_;
    \$self->{STIG_ID}  = '$5';
    return \$self->{STIG_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$RULE_TITLE = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->RULE_TITLE();
#
# DESCRIPTION
#   Returns the plugins RULE TITLE
#
# ------------------------------------------------------------------------------

sub RULE_TITLE {
    my (\$self) = \@_;
    \$self->{RULE_TITLE} = '$6';
    return \$self->{RULE_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$DISCUSSION = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->DISCUSSION();
#
# DESCRIPTION
#   Returns the plugins DISCUSSION text
#
# ------------------------------------------------------------------------------

sub DISCUSSION {
    my (\$self) = \@_;
    \$self->{DISCUSSION} = <<'DISCUSSION';
$7
DISCUSSION
    return \$self->{DISCUSSION};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$CHECK_CONTENT = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->CHECK_CONTENT();
#
# DESCRIPTION
#   Returns the plugins CHECK CONTENT text
#
# ------------------------------------------------------------------------------

sub CHECK_CONTENT {
    my (\$self) = \@_;
    \$self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
$8
CHECK_CONTENT
    return \$self->{CHECK_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$FIX_CONTENT = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->FIX_CONTENT();
#
# DESCRIPTION
#   Returns the plugins FIX CONTENT text
#
# ------------------------------------------------------------------------------

sub FIX_CONTENT {
    my (\$self) = \@_;
    \$self->{FIX_CONTENT} = <<'FIX_CONTENT';
$9
FIX_CONTENT
    return \$self->{FIX_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   \$CCI = $PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2]->CCI();
#
# DESCRIPTION
#   Returns the plugins CCI text
#
# ------------------------------------------------------------------------------

sub CCI {
    my (\$self) = \@_;
    \$self->{CCI} = <<'CCI';
$10
CCI
    return \$self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
TEMPLATE

    my $NEWFILE = "$PACKAGENAME[0]_$PACKAGENAME[1]_$PACKAGENAME[2].pm";
    open my $OFH, '>:encoding(utf8)',
        File::Spec::Functions::catdir( $FindBin::Bin, qw(.. plugins RHEL6),
        $NEWFILE );
    print {$OFH} $TEMPLATE;
    close $OFH;
}

# ------------------------------------------------------------------------------

__END__
