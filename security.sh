#!/bin/bash
# --- coding: utf-8 ---
#Filename:   security.sh
#Date:       2022-02-07 16:44:51

#Run this shell to automaticly seting your security baseline in your mackine

ACTION_FUNCTION="/etc/rc.d/init.d/functions"
TRASH_LOG="trash_log.log"
CHECK_LOG="check_log.log"

if [ ! -f ${ACTION_FUNCTION} ]; then
    echo "action function doesn't exist, please check your system version"
    exit 1
fi

source ${ACTION_FUNCTION}
touch ${TRASH_LOG}
touch ${CHECK_LOG}


echo "-------------------------Check user-------------------------"

if [ ! $(whoami) = "root" ]; then
    action "Checking user " /bin/false
    echo "user should be root to run this shell code"
    echo "try `su root` in your bash"
    exit 1
else
    action "Checking user " /bin/true
fi

echo -e "----------------------------done----------------------------\n"


echo "------------Checking SSH connect time-out config------------"

ClientAliveInterval=$(sudo cat /etc/ssh/sshd_config | grep "ClientAliveInterval" | awk '{print $2}')
line=$(sudo cat /etc/ssh/sshd_config | grep -n "ClientAliveInterval" | awk -F: '{print $1}')
if [ ${ClientAliveInterval} -gt 300 ]; then
    eval "sudo sed -i '${line}s/.*/ClientAliveInterval 300/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking ClientAliveInterval " /bin/true || action "Checking ClientAliveInterval " /bin/false
    echo "ClientAliveInterval should less than 300 seconds, already change your setting from ${ClientAliveInterval} to 300" >>${CHECK_LOG}
else
    action "Checking ClientAliveInterval " /bin/true 
fi

ClientAliveCountMax=$(sudo cat /etc/ssh/sshd_config | grep "ClientAliveCountMax" | awk '{print $2}')
line=$(sudo cat /etc/ssh/sshd_config | grep -n "ClientAliveCountMax" | awk -F: '{print $1}')
if [ ${ClientAliveCountMax} -gt 2 ]; then
    eval "sudo sed -i '${line}s/.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking ClientAliveCountMax " /bin/true || action "Checking ClientAliveCountMax " /bin/false
    echo "ClientAliveCountMax should less than 2 times, already change your setting form ${ClientAliveCountMax} to 2" >>${CHECK_LOG}
else
    action "Checking ClientAliveCountMax " /bin/true 
fi

echo -e "----------------------------done----------------------------\n"


echo "-------------Checking SSH authorization config--------------"

MaxAuthTries=$(sudo grep "MaxAuthTries" /etc/ssh/sshd_config)
if [ ! $? -eq 0 ]; then
    echo "MaxAuthTries 3" >>/etc/ssh/sshd_config
else
    MaxAuthTries=$(sudo cat /etc/ssh/sshd_config | grep "MaxAuthTries" | awk '{print $2}')
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "MaxAuthTries" | awk -F: '{print $1}')
    if [ ${MaxAuthTries} -gt 3 ]; then
        eval "sudo sed -i '${line}s/.*/MaxAuthTries 3/' /etc/ssh/sshd_config"
        [ $? -eq 0 ] && action "Checking MaxAuthTries " /bin/true || action "Checking MaxAuthTries " /bin/false
        echo "MaxAuthTries should less than 3 times, already change your setting from ${MaxAuthTries} to 3" >>${CHECK_LOG}
    else
        action "Checking MaxAuthTries " /bin/true 
    fi
fi

PermitEmptyPasswords=$(sudo grep "PermitEmptyPasswords" /etc/ssh/sshd_config)
if [ ! $? -eq 0 ]; then
    echo "PermitEmptyPasswords no" >>/etc/ssh/sshd_config
else
    PermitEmptyPasswords=$(sudo cat /etc/ssh/sshd_config | grep "PermitEmptyPasswords" | awk '{print $2}')
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "PermitEmptyPasswords" | awk -F: '{print $1}')
    if [ ${PermitEmptyPasswords} = "yes" ]; then
        eval "sudo sed -i '${line}s/.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"
        [ $? -eq 0 ] && action "Checking PermitEmptyPasswords " /bin/true || action "Checking PermitEmptyPasswords " /bin/false
        echo "PermitEmptyPasswords should be no, already change your setting from ${PermitEmptyPasswords} to no" >>${CHECK_LOG}
    else
        action "Checking PermitEmptyPasswords " /bin/true 
    fi
fi

line=$(sudo cat /etc/ssh/sshd_config | grep -n "PermitUserEnvironment" | awk -F: '{print $1}')
eval "sudo sed -i '${line}s/.*/PermitUserEnvironment no/' /etc/ssh/sshd_config"
[ $? -eq 0 ] && action "Checking PermitUserEnvironment " /bin/true || action "Checking PermitUserEnvironment " /bin/false
echo "PermitUserEnvironment should be no, already change your setting to no" >>${CHECK_LOG}

PermitRootLogin=$(sudo cat /etc/ssh/sshd_config | grep "PermitRootLogin" | awk '{print $2}')
PermitRootLogin=$(echo ${PermitRootLogin} | awk '{print $1}')
line=$(sudo cat /etc/ssh/sshd_config | grep -n "PermitRootLogin" | awk -F: '{print $1}')
line=$(echo ${line} | awk '{print $1}')
if [ ${PermitRootLogin} = "yes" ]; then
    eval "sudo sed -i '${line}s/.*/PermitRootLogin no/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking PermitRootLogin " /bin/true || action "Checking PermitRootLogin " /bin/false
    echo "PermitRootLogin should be no, already change your setting from ${PermitRootLogin} to no" >>${CHECK_LOG}
else
    action "Checking PermitRootLogin " /bin/true 
fi

#echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >>/etc/ssh/sshd_config
#[ $? -eq 0 ] && action "Checking MAC algorithm " /bin/true || action "Checking MAC algorithm " /bin/false

LoginGraceTime=$(sudo grep "LoginGraceTime" /etc/ssh/sshd_config)
if [ ! $? -eq 0 ]; then
    echo "LoginGraceTime 60" >>/etc/ssh/sshd_config
else
    LoginGraceTime=$(sudo cat /etc/ssh/sshd_config | grep "LoginGraceTime" | awk '{print $2}')
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "LoginGraceTime" | awk -F: '{print $1}')
    if [ ! ${LoginGraceTime} = "60" ]; then
        eval "sudo sed -i '${line}s/.*/LoginGraceTime 60/' /etc/ssh/sshd_config"
        [ $? -eq 0 ] && action "Checking LoginGraceTime " /bin/true || action "Checking LoginGraceTime " /bin/false
        echo "LoginGraceTime should be equal to 60 seconds, already change your setting from ${LoginGraceTime} to 60" >>${CHECK_LOG}
    else
        action "Checking LoginGraceTime " /bin/true 
    fi
fi

#Protocol=$(sudo grep "Protocol" /etc/ssh/sshd_config)
#if [ ! $? -eq 0 ]; then
#    echo "Protocol 2" >>/etc/ssh/sshd_config
#else
#    Protocol=$(sudo cat /etc/ssh/sshd_config | grep "Protocol" | awk '{print $2}')
#    line=$(sudo cat /etc/ssh/sshd_config | grep -n "Protocol" | awk -F: '{print $1}')
#    if [ ! ${Protocol} -eq 2 ]; then
#        eval "sudo sed -i '${line}s/.*/Protocol 2/' /etc/ssh/sshd_config"
#        [ $? -eq 0 ] && action "Checking Protocol " /bin/true || action "Checking Protocol " /bin/false
#        echo "Protocol should be 2, already change your setting from ${Protocol} to 2" >>${CHECK_LOG}
#    else
#        action "Checking Protocol " /bin/true 
#    fi
#fi

LogLevel=$(sudo grep "LogLevel" /etc/ssh/sshd_config)
if [ ! $? -eq 0 ]; then
    echo "LogLevel INFO" >>/etc/ssh/sshd_config
else
    LogLevel=$(sudo cat /etc/ssh/sshd_config | grep "LogLevel" | awk '{print $2}')
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "LogLevel" | awk -F: '{print $1}')
    eval "sudo sed -i '${line}s/.*/LogLevel INFO/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking LogLevel " /bin/true || action "Checking LogLevel " /bin/false
    echo "LogLevel should be INFO, already change your setting from ${LogLevel} to INFO" >>${CHECK_LOG}
fi

X11Forwarding=$(sudo cat /etc/ssh/sshd_config | grep "X11Forwarding" | awk '{print $2}')
X11Forwarding=$(echo ${X11Forwarding} | awk '{print $1}')
if [ ! $? -eq 0 ]; then
    echo "X11Forwarding no" >>/etc/ssh/sshd_config
else
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "X11Forwarding" | awk -F: '{print $1}')
    line=$(echo ${line} | awk '{print $1}')
    eval "sudo sed -i '${line}s/.*/X11Forwarding no/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking X11Forwarding " /bin/true || action "Checking X11Forwarding " /bin/false
    echo "X11Forwarding should be no, already change your setting from ${X11Forwarding} to INFO" >>${CHECK_LOG}
fi

IgnoreRhosts=$(sudo grep "IgnoreRhosts" /etc/ssh/sshd_config)
if [ ! $? -eq 0 ]; then
    echo "IgnoreRhosts yes" >>/etc/ssh/sshd_config
else
    IgnoreRhosts=$(sudo cat /etc/ssh/sshd_config | grep "IgnoreRhosts" | awk '{print $2}')
    line=$(sudo cat /etc/ssh/sshd_config | grep -n "IgnoreRhosts" | awk -F: '{print $1}')
    eval "sudo sed -i '${line}s/.*/IgnoreRhosts yes/' /etc/ssh/sshd_config"
    [ $? -eq 0 ] && action "Checking IgnoreRhosts " /bin/true || action "Checking IgnoreRhosts " /bin/false
    echo "IgnoreRhosts should be yes, already change your setting from ${IgnoreRhosts} to yes" >>${CHECK_LOG}
fi

#HostbasedAuthentication=$(sudo cat /etc/ssh/sshd_config | grep "HostbasedAuthentication" | awk '{print $2}')
#HostbasedAuthentication=$(echo ${HostbasedAuthentication} | awk '{print $1}')
#if [ ! $? -eq 0 ]; then
#    echo "HostbasedAuthentication no" >>/etc/ssh/sshd_config
#else
#    line=$(sudo cat /etc/ssh/sshd_config | grep -n "HostbasedAuthentication" | awk -F: '{print $1}')
#    line=$(echo ${line} | awk '{print $1}')
#    eval "sudo sed -i '${line}s/.*/HostbasedAuthentication no/' /etc/ssh/sshd_config"
#    [ $? -eq 0 ] && action "Checking HostbasedAuthentication " /bin/true || action "Checking HostbasedAuthentication " /bin/false
#    echo "HostbasedAuthentication should be no, already change your setting from ${HostbasedAuthentication} to no" >>${CHECK_LOG}
#fi

echo -e "----------------------------done----------------------------\n"


echo "-------------------Checking SSH IP config-------------------"

sudo echo "sshd:123.126.82.37:allow" >>/etc/hosts.allow && sudo echo "sshd:10.0.*.*:allow" >>/etc/hosts.allow && sudo echo "sshd:ALL" >>/etc/hosts.deny
[ $? -eq 0 ] && action "Checking SSH IP config " /bin/true || action "Checking SSH IP config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "--------------------Restart sshd service--------------------"

sudo service sshd restart | sudo tee ${TRASH_LOG}
[ $? -eq 0 ] && action "Restart sshd service " /bin/true || action "Restart sshd service " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-------------Checking user authorization config-------------"

eval "sudo sed -i '1a auth        required      pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog' /etc/pam.d/password-auth"
[ $? -eq 0 ] && action "Checking user authorization config " /bin/true || action "Checking user authorization config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "--------------------Checking user umask---------------------"

eval "sudo sed -i 's/if [ $UID -gt 199 ] && [ "$(/usr/bin/id -gn)" = "$(/usr/bin/id -un)" ]; then/if [ $(whoami) = "oushu" -o $(whoami) = "root" ]; then/' /etc/bashrc" 
[ $? -eq 0 ] && eval "sudo sed -i 's/umask 002/umask 077/' /etc/bashrc" 
[ $? -eq 0 ] && eval "sudo sed -i 's/umask 022/umask 027/' /etc/bashrc"
[ $? -eq 0 ] && eval "sudo sed -i 's/if [ $UID -gt 199 ] && [ "$(/usr/bin/id -gn)" = "$(/usr/bin/id -un)" ]; then/if [ $(whoami) = "oushu" -o $(whoami) = "root" ]; then/' /etc/profile" 
[ $? -eq 0 ] && eval "sudo sed -i 's/umask 002/umask 077/' /etc/profile" 
[ $? -eq 0 ] && eval "sudo sed -i 's/umask 022/umask 027/' /etc/profile"
[ $? -eq 0 ] && action "Checking user umask " /bin/true || action "Checking user umask " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "---------------Checking bash time_out config----------------"

echo "TMOUT=600" >>/etc/bashrc
[ $? -eq 0 ] && action "Checking bash time_out config " /bin/true || action "Checking user authorization config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-------------Checking loaded file system module-------------"

touch /etc/modprobe.d/CIS.conf
fs_list=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat)
for fs in ${fs_list[*]}; do
    echo "install ${fs} /bin/false" >>/etc/modprobe.d/CIS.conf
    lsmod | grep "${fs}" >${TRASH_LOG}
    if [ $? -eq 0 ]; then
        rmmod ${fs} >${TRASH_LOG}
        echo "${fs} should not load in module, already remove it" >>${CHECK_LOG}
    fi
    lsmod | grep "${fs}" >${TRASH_LOG}
    [ $? -eq 1 ] && action "Checking ${fs} module " /bin/true || action "Checking ${fs} module " /bin/false
done

echo -e "----------------------------done----------------------------\n"


echo "---------------------Checking aide cron----------------------"

sudo yum -y install aide
[ $? -eq 0 ] && aide --init || echo "install aide fail"
[ $? -eq 0 ] && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz || echo "init aide fail"
[ $? -eq 0 ] && echo "00 05 * * * root /usr/sbin/aide --check >/tmp/aide-check-` date +%Y%m%d `.log" >>/etc/crontab || echo "add aide to crontab fail"
[ $? -eq 0 ] && action "Checking aide cron" /bin/true || action "Checking aide cron" /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-----------------Checking bootloader config-----------------"

chown root:root /boot/grub2/grub.cfg && chmod og-rwx /boot/grub2/grub.cfg
[ $? -eq 0 ] && action "Checking bootloader config " /bin/true || action "Checking bootloader config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-----------------Checking core dump config------------------"

sudo echo "*     hard       core     0" >>/etc/security/limits.conf && echo "fs.suid_dumpable = 0" >>/etc/sysctl.conf && sudo sysctl -w fs.suid_dumpable=0 && echo "kernel.randomize_va_space = 2" >>/etc/sysctl.conf && sudo sysctl -w kernel.randomize_va_space=2
[ $? -eq 0 ] && action "Checking core dump config " /bin/true || action "Checking core dump config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "------------------Checking network config-------------------"

echo "net.ipv4.ip_forward = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.ip_forward=0
[ $? -eq 0 ] && echo "net.ipv4.conf.all.send_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv4.conf.default.send_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.all.accept_source_route=0
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.default.accept_source_route=0
[ $? -eq 0 ] && echo "net.ipv4.conf.all.accept_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv4.conf.default.accept_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.all.accept_redirects=0
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.default.accept_redirects=0
[ $? -eq 0 ] && echo "net.ipv4.conf.all.secure_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv4.conf.default.secure_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.all.secure_redirects=0
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.default.secure_redirects=0
[ $? -eq 0 ] && echo "net.ipv4.conf.all.log_martians = 1" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv4.conf.default.log_martians = 1" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.all.log_martians=1
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.default.log_martians=1
[ $? -eq 0 ] && echo "net.ipv4.conf.all.rp_filter = 1" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv4.conf.default.rp_filter = 1" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.all.rp_filter=1
[ $? -eq 0 ] && sysctl -w net.ipv4.conf.default.rp_filter=1
[ $? -eq 0 ] && echo "net.ipv4.tcp_syncookies = 1" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv4.tcp_syncookies=1
[ $? -eq 0 ] && echo "net.ipv6.conf.all.accept_ra = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv6.conf.default.accept_ra = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv6.conf.all.accept_ra=0
[ $? -eq 0 ] && sysctl -w net.ipv6.conf.default.accept_ra=0
[ $? -eq 0 ] && echo "net.ipv6.conf.all.accept_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && echo "net.ipv6.conf.default.accept_redirects = 0" >>/etc/sysctl.conf
[ $? -eq 0 ] && sysctl -w net.ipv6.conf.all.accept_redirects=0
[ $? -eq 0 ] && sysctl -w net.ipv6.conf.default.accept_redirects=0
[ $? -eq 0 ] && sysctl -w net.ipv4.route.flush=1
[ $? -eq 0 ] && line=$(sudo cat /etc/ssh/sshd_config | grep -n "GRUB_CMDLINE_LINUX" | awk -F: '{print $1}')
[ $? -eq 0 ] && eval "sudo sed -i '${line}s/\"/\./' /etc/sysctl.conf"
[ $? -eq 0 ] && eval "sudo sed -i '${line}s/\"/ ipv6.disable=1 audit=1\"/' /etc/sysctl.conf"
[ $? -eq 0 ] && eval "sudo sed -i '${line}s/\./\"/' /etc/sysctl.conf"
[ $? -eq 0 ] && grub2-mkconfig -o /boot/grub2/grub.cfg
[ $? -eq 0 ] && grub2-mkconfig > /boot/grub2/grub.cfg
[ $? -eq 0 ] && action "Checking network config " /bin/true || action "Checking network config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-------------Checking tranfer control protocols-------------"

pr_list=(dccp sctp rds tipc)
for pr in ${pr_list[*]}; do
    echo "install ${pr} /bin/false" >>/etc/modprobe.d/CIS.conf
done
[ $? -eq 0 ] && action "Checking tranfer control protocols " /bin/true || action "Checking tranfer control protocols " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "----------------Checking crontab permission-----------------"

cron_list=(crontab cron.hourly cron.daily cron.weekly cron.monthly cron.d)
for cron in ${cron_list[*]}; do
    chown root:root /etc/${cron} && chmod og-rwx /etc/${cron}
    [ $? -eq 0 ] && action "Checking ${cron} file " /bin/true || action "Checking ${cron} file " /bin/false
done
[ $? -eq 0 ] && action "Checking crontab permission " /bin/true || action "Checking crontab permission " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "----------------Checking yum gpgcheck config----------------"

gpgcheck=$(sudo cat /etc/yum.conf | grep "gpgcheck" | awk -F= '{print $2}')
if [ ! $? -eq 0 ]; then
    echo "gpgcheck=1" >>/etc/yum.conf
else
    line=$(sudo cat /etc/yum.conf | grep -n "gpgcheck" | awk -F: '{print $1}')
    if [ ${gpgcheck} = "0" ]; then
        eval "sudo sed -i '${line}s/.*/gpgcheck=1/' /etc/yum.conf"
        [ $? -eq 0 ] && action "Checking gpgcheck " /bin/true || action "Checking gpgcheck " /bin/false
        echo "gpgcheck should be equals to 1, already change your setting from ${gpgcheck} to 1" >>${CHECK_LOG}
    fi
fi

f_list=$(ls /etc/yum.repos.d/)
for f in ${f_list}; do
    gpgcheck=$(sudo cat /etc/yum.repos.d/${f} | grep "gpgcheck" | awk -F= '{print $2}')
    if [ ! $? -eq 0 ]; then
        echo "gpgcheck=1" >>/etc/yum.repos.d/${f}
    else
        line=$(sudo cat /etc/yum.repos.d/${f} | grep -n "gpgcheck" | awk -F: '{print $1}')
        if [ ${gpgcheck} = "0" ]; then
            eval "sudo sed -i '${line}s/.*/gpgcheck=1/' /etc/yum.repos.d/${f}"
            [ $? -eq 0 ] && action "Checking gpgcheck " /bin/true || action "Checking gpgcheck " /bin/false
            echo "gpgcheck should be equals to 1, already change your setting from ${gpgcheck} to 1" >>${CHECK_LOG}
        fi
    fi
done
[ $? -eq 0 ] && action "Checking yum gpgcheck config " /bin/true || action "Checking yum gpgcheck config " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "------------------Checking sudo audit log--------------------"

echo "-w /etc/sudoers -p wa -k scope" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/sudoers.d/ -p wa -k scope" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/log/sudo.log -p wa -k actions" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-e 2" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && sudo service auditd restart >${TRASH_LOG}
[ $? -eq 0 ] && action "Checking sudo audit log " /bin/true || action "Checking sudo audit log " /bin/false

echo -e "----------------------------done----------------------------\n"


echo "-----------------Checking system log config------------------"

echo "-w /etc/sudoers -p wa -k scope" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/sudoers.d/ -p wa -k scope" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/log/sudo.log -p wa -k actions" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-e 2" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/group -p wa -k identity" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/passwd -p wa -k identity" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/gshadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/shadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/security/opasswd -p wa -k identity" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /etc/selinux/ -p wa -k MAC-policy" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/log/lastlog -p wa -k logins" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/run/faillock/ -p wa -k logins" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/run/utmp -p wa -k session" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/log/wtmp -p wa -k logins" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && echo "-w /var/log/btmp -p wa -k logins" >>/etc/audit/rules.d/audit.rules
[ $? -eq 0 ] && sudo service auditd restart >${TRASH_LOG}
[ $? -eq 0 ] && action "Checking system log config " /bin/true || action "Checking system log config " /bin/false

echo -e "----------------------------done----------------------------\n"
