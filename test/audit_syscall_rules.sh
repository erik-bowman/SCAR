#!/usr/bin/env bash

function heal {
    local tool="$1"
    local pattern="$2"
    local group="$3"
    local arch="$4"
    local full_rule="$5"

    if [ $# -ne "5" ]
    then
            exit 1
    fi

    declare -a files_to_inspect
    if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
    then
            exit 1
    elif [ "$tool" == 'auditctl' ]
    then
            files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
    elif [ "$tool" == 'augenrules' ]
    then
            key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
            # Check if particular audit rule is already defined
            IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
            unset $IFS
            for match in "${matches[@]}"
            do
                    files_to_inspect=("${files_to_inspect[@]}" "${match}")
            done
            if [ ${#files_to_inspect[@]} -eq "0" ]
            then
                    files_to_inspect="/etc/audit/rules.d/$key.rules"
                    if [ ! -e "$files_to_inspect" ]
                    then
                            touch "$files_to_inspect"
                            chmod 0640 "$files_to_inspect"
                    fi
            fi
    fi

    local append_expected_rule=0

    for audit_file in "${files_to_inspect[@]}"
    do
            IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
            unset $IFS

            for rule in "${existing_rules[@]}"
            do
                    rule_esc=${rule//$'/'/$'\/'}
                    if [ "${rule}" != "${full_rule}" ]
                    then
                            rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                            if grep -q -- "$rule_syscalls" <<< "$full_rule"
                            then
                                    sed -i -e "/$rule_esc/d" "$audit_file"
                                    existing_rules=("${existing_rules[@]//$rule/}")
                            else
                                    sed -i -e "/$rule_esc/d" "$audit_file"
                                    IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                    unset $IFS
                                    new_syscalls_for_rule=''
                                    for syscall_arg in "${rule_syscalls_as_array[@]}"
                                    do
                                            if [ "$syscall_arg" == '' ]
                                            then
                                                    continue
                                            fi
                                            if grep -q -v -- "$group" <<< "$syscall_arg"
                                            then
                                                    new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                            fi
                                    done
                                    updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                    updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                    if ! grep -q -- "$updated_rule" "$audit_file"
                                    then
                                            echo "$updated_rule" >> "$audit_file"
                                    fi
                            fi
                    else
                            append_expected_rule=1
                    fi
            done
            if [[ ${append_expected_rule} -eq "0" ]]
            then
                    echo "$full_rule" >> "$audit_file"
            fi
    done
}

[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

		PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"

		if [ ${ARCH} = "b32" ]
		then
				GROUP="\(chown\|fchown\|lchown\|fchownat\|chmod\|fchmod\|fchmodat\|setxattr\|fsetxattr\|lsetxattr\|removexattr\|fremovexattr\|lremovexattr\)"
				FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S lchown -S fchownat -S chmod -S fchmod -S fchmodat -S setxattr -S fsetxattr -S lsetxattr -S removexattr -S fremovexattr -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
		elif [ ${ARCH} = "b64" ]
		then
				GROUP="\(chown\|fchown\|lchown\|fchownat\|chmod\|fchmod\|fchmodat\|setxattr\|fsetxattr\|lsetxattr\|removexattr\|fremovexattr\|lremovexattr\)"
				FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S lchown -S fchownat -S chmod -S fchmod -S fchmodat -S setxattr -S fsetxattr -S lsetxattr -S removexattr -S fremovexattr -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
		fi
		case $1 in
		'check')
			check "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
			check "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
			;;
		'heal')
			heal "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
			heal "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
			;;
		esac

done
