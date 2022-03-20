#!/bin/bash
# sh os7init.sh  主机名

# 检查是否为root用户，脚本必须在root权限下运行
if [[ "$(whoami)" != "root" ]]; then
    echo "please run this script as root !" >&2
    exit 1
fi
echo -e "\033[31m the script only Support CentOS_7 x86_64 \033[0m"
echo -e "\033[31m system initialization script, Please Seriously. press ctrl+C to cancel \033[0m"

# 检查是否为64位系统，这个脚本只支持64位脚本
platform=`uname -i`
if [ $platform != "x86_64" ];then
    echo "this script is only for 64bit Operating System !"
    exit 1
fi

if [ "$1" == "" ];then
    echo "The host name is empty."
    exit 1
else
	hostnamectl set-hostname  $1
	hostnamectl set-hostname "$1" --static
	systemctl restart systemd-hostnamed
fi

cat << EOF
+---------------------------------------+
|   your system is CentOS 7 x86_64      |
|           start optimizing            |
+---------------------------------------+
EOF
sleep 1

# 安装必要支持工具及软件工具
yum_update(){
yum update -y --exclude=kernel* --exclude=centos-release*
yum install -y epel-release nmap unzip wget vim lsof xz net-tools iptables-services ntpdate ntp-doc psmisc mlocate bash-completion htop
}

# 设置时间同步 set time
zone_time(){
timedatectl set-timezone Asia/Shanghai
ntpdate ntp.aliyun.com
hwclock -w
sed -i 's%SYNC_HWCLOCK=no%SYNC_HWCLOCK=yes%' /etc/sysconfig/ntpdate
echo "* 23 * * * root /usr/sbin/ntpdate ntp.aliyun.com" >> /etc/crontab && crontab /etc/crontab 
}

# 修改文件打开数 set the file limit
limits_config(){
cat > /etc/rc.d/rc.local << EOF
#!/bin/bash

touch /var/lock/subsys/local
ulimit -SHn 1024000
EOF

sed -i "/^ulimit -SHn.*/d" /etc/rc.d/rc.local
echo "ulimit -SHn 1024000" >> /etc/rc.d/rc.local

sed -i "/^ulimit -s.*/d" /etc/profile
sed -i "/^ulimit -c.*/d" /etc/profile
sed -i "/^ulimit -SHn.*/d" /etc/profile

cat >> /etc/profile << EOF
ulimit -c unlimited
ulimit -s unlimited
ulimit -SHn 1024000
EOF

source /etc/profile
ulimit -a
cat /etc/profile | grep ulimit

if [ ! -f "/etc/security/limits.conf.bak" ]; then
    cp /etc/security/limits.conf /etc/security/limits.conf.bak
fi

cat > /etc/security/limits.conf << EOF
* soft nofile 1024000
* hard nofile 1024000
* soft nproc  1024000
* hard nproc  1024000
hive   - nofile 1024000
hive   - nproc  1024000
EOF

if [ ! -f "/etc/security/limits.d/20-nproc.conf.bak" ]; then
    cp /etc/security/limits.d/20-nproc.conf /etc/security/limits.d/20-nproc.conf.bak
fi

cat > /etc/security/limits.d/20-nproc.conf << EOF
*          soft    nproc     409600
root       soft    nproc     unlimited
EOF

sleep 1
}

# 优化内核参数 tune kernel parametres
sysctl_config(){
if [ ! -f "/etc/sysctl.conf.bak" ]; then
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
fi

#add
cat > /etc/sysctl.conf << EOF
vm.swappiness = 0
kernel.sysrq = 1

net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.lo.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2

net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
# 内核4.12+移除此参数
net.ipv4.tcp_tw_recycle = 1

net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

modprobe br_netfilter
#reload sysctl
/sbin/sysctl -p
sleep 1
}

# 设置UTF-8   LANG="zh_CN.UTF-8"
LANG_config(){
echo "LANG=\"en_US.UTF-8\"">/etc/locale.conf
source  /etc/locale.conf
}


#关闭SELINUX disable selinux
selinux_config(){
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
setenforce 0
}

#日志处理
log_config(){
setenforce 0
systemctl start systemd-journald
systemctl status systemd-journald
}


# 关闭防火墙
firewalld_config(){
/usr/bin/systemctl stop  firewalld.service
/usr/bin/systemctl disable  firewalld.service
}


# SSH配置优化 set sshd_config
sshd_config(){
if [ ! -f "/etc/ssh/sshd_config.bak" ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
fi

cat >/etc/ssh/sshd_config<<EOF
Port 66
AddressFamily inet
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
MaxAuthTries 4
# RSAAuthentication yes
# 关闭基于GSSAPI 的用户认证
GSSAPIAuthentication no
# 关闭S/KEY（质疑-应答)认证方式
ChallengeResponseAuthentication no
# 关闭ssh的tcp转发
AllowTcpForwarding no
# SSH空闲超时退出时间
ClientAliveInterval 60
ClientAliveCountMax 4
TCPKeepAlive no

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
# 禁止空密码登陆
PermitEmptyPasswords no
# 禁止root登陆
PermitRootLogin no
UsePAM yes
UseDNS no
X11Forwarding yes
LoginGraceTime 60
UsePrivilegeSeparation sandbox
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem       sftp    /usr/libexec/openssh/sftp-server
Banner /etc/ssh/alert
EOF

cat >/etc/ssh/alert<<EOF

Authorized users only. All activity may be monitored and reported.

EOF

cat >/etc/motd<<EOF
*******************************************************
Warning!!!Any Access Without Permission Is Forbidden!!!
*******************************************************
EOF

/sbin/service sshd restart
}


# 关闭ipv6  disable the ipv6
ipv6_config(){
echo "NETWORKING_IPV6=no">/etc/sysconfig/network
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo "127.0.0.1   localhost   localhost.localdomain">/etc/hosts
#sed -i 's/IPV6INIT=yes/IPV6INIT=no/g' /etc/sysconfig/network-scripts/ifcfg-enp0s8


for line in $(ls -lh /etc/sysconfig/network-scripts/ifcfg-* | awk -F '[ ]+' '{print $9}')
do
if [ -f  $line ]
        then
        sed -i 's/IPV6INIT=yes/IPV6INIT=no/g' $line
                echo $i
fi
done
}


# 设置历史命令记录格式 history
history_config(){
export HISTFILESIZE=10000000
export HISTSIZE=1000000
export PROMPT_COMMAND="history -a"
export HISTTIMEFORMAT="%Y-%m-%d_%H:%M:%S "
##export HISTTIMEFORMAT="{\"TIME\":\"%F %T\",\"HOSTNAME\":\"\$HOSTNAME\",\"LI\":\"\$(who -u am i 2>/dev/null| awk '{print \$NF}'|sed -e 's/[()]//g')\",\"LU\":\"\$(who am i|awk '{print \$1}')\",\"NU\":\"\${USER}\",\"CMD\":\""
cat >>/etc/bashrc<<EOF
alias vi='vim'
HISTDIR='/var/log/command.log'
if [ ! -f \$HISTDIR ];then
touch \$HISTDIR
chmod 666 \$HISTDIR
fi
export HISTTIMEFORMAT="{\"TIME\":\"%F %T\",\"IP\":\"\$(ip a | grep -E '192.168|172' | head -1 | awk '{print \$2}' | cut -d/ -f1)\",\"LI\":\"\$(who -u am i 2>/dev/null| awk '{print \$NF}'|sed -e 's/[()]//g')\",\"LU\":\"\$(who am i|awk '{print \$1}')\",\"NU\":\"\${USER}\",\"CMD\":\""
export PROMPT_COMMAND='history 1|tail -1|sed "s/^[ ]\+[0-9]\+  //"|sed "s/$/\"}/">> /var/log/command.log'
EOF
source /etc/bashrc
}

# SHELL窗口超时时间
tmout_config(){
echo "export TMOUT=600" >>/etc/profile
source /etc/profile
}

# 服务优化设置
service_config(){
/usr/bin/systemctl enable NetworkManager-wait-online.service
/usr/bin/systemctl start NetworkManager-wait-online.service
/usr/bin/systemctl stop postfix.service
/usr/bin/systemctl disable postfix.service
chmod +x /etc/rc.local
chmod +x /etc/rc.d/rc.local
#ls -l /etc/rc.d/rc.local

# 禁止Control-Alt-Delete 键盘重启系统命令
rm -rf /usr/lib/systemd/system/ctrl-alt-del.target

# 隐藏系统版本信息
mv /etc/issue /etc/issue.bak 
mv /etc/issue.net /etc/issue.net.bak
}

userpwd_config(){
# 设置密码安全策略
## 备份文件
cp /etc/login.defs /etc/login.defs.back

## 注释旧文件
sed -i 's%^PASS_%#PASS_%' /etc/login.defs

## 插入新密码过期配置
cat >> /etc/login.defs << EOF
# 密码最长过期天数
PASS_MAX_DAYS 120
# 密码最小过期天数　      
PASS_MIN_DAYS 7
# 密码最小长度　　　    
PASS_MIN_LEN 8
# 密码过期警告天数　  
PASS_WARN_AGE 30
EOF

# 设置密码强度
### 检查是否安装了 pam_pwquality 模块
rpm -qa | grep pwquality

# 备份文件
cp /etc/pam.d/passwd /etc/pam.d/passwd.back

# 插入模块
echo "password   required     pam_pwquality.so retry=3" >> /etc/pam.d/passwd

## 插入新密码过期配置
cat >> /etc/security/pwquality.conf << EOF
# 新密码与前一个旧密码之间至少有 M 个字符不相同
difok = 3
# 密码最小长度
minlen = 8
# 密码中至少有几个数字（至少 N<0 或至多 N>=0）
dcredit = -1
# 密码中至少有几个大写字母（至少 N<0 或至多 N>=0）
ucredit = -1
# 密码中至少有几个小写字母（至少 N<0 或至多 N>=0）
lcredit = -1
# 密码中至少有几个特殊字符（至少 N<0 或至多 N>=0）
ocredit = -1
# 密码要包含全部四种字符（数字、大、小写、特殊字符）
#minclass = 4
# 新密码中允许的最大连续相同字符数
#maxrepeat = 3
# 完全相同的连续字符也不能超过 N 个
#maxclassrepeat = 3
# 检查passwd条目的GECOS字段的长度超过3个字符的字是否包含在新密码中
gecoscheck = 2
EOF


# 下次登陆强制修改密码
# chage -d0 test

# 新增eproot管理员
# useradd -m -s /bin/bash eproot

# 禁用不用的用户
sed -i 's%^adm%#adm%' /etc/passwd
sed -i 's%^lp%#lp%' /etc/passwd
sed -i 's%^sync%#sync%' /etc/passwd
sed -i 's%^shutdown%#shutdown%' /etc/passwd
sed -i 's%^halt%#halt%' /etc/passwd
sed -i 's%^operator%#operator%' /etc/passwd
sed -i 's%^games%#games%' /etc/passwd
sed -i 's%^ftp%#ftp%' /etc/passwd
sed -i 's%^news%#news%' /etc/passwd
sed -i 's%^uucp%#uucp%' /etc/passwd
sed -i 's%^gopher%#gopher%' /etc/passwd
sed -i 's%^dip%#dip%' /etc/passwd
sed -i 's%^postfix%#postfix%' /etc/passwd
# 禁用不用的用户组
sed -i 's%^adm%#adm%' /etc/group
sed -i 's%^lp%#lp%' /etc/group
sed -i 's%^cdrom%#cdrom%' /etc/group
sed -i 's%^floppy%#floppy%' /etc/group
sed -i 's%^games%#games%' /etc/group
sed -i 's%^ftp%#ftp%' /etc/group
sed -i 's%^news%#news%' /etc/group
sed -i 's%^uucp%#uucp%' /etc/group
sed -i 's%^dip%#dip%' /etc/group
sed -i 's%^pppusers%#pppusers%' /etc/group
sed -i 's%^audio%#audio%' /etc/group
}

# VIM设置
vim_config(){
cat >> /etc/vimrc  << EOF
set history=1000
autocmd InsertLeave * se cul
autocmd InsertLeave * se nocul
set nu
set bs=2
syntax on
set laststatus=2
set tabstop=4
set go=
set ruler
set showcmd
set cmdheight=1
hi CursorLine   cterm=NONE ctermbg=blue ctermfg=white guibg=blue guifg=white
set hls
set cursorline
set ignorecase
set hlsearch
set incsearch
set helplang=cn
set paste
EOF
}

# fail2ban设置
fail2ban_config(){
yum -y install epel-release
yum -y install fail2ban

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8,10.0.0.0/8
bantime = 86400
findtime = 600
maxretry = 4
[sshd]
enabled  = true
filter   = sshd
action   = iptables[name=SSH, port=66, protocol=tcp]
logpath  = /var/log/secure
EOF
systemctl start fail2ban && systemctl enable fail2ban

}


# done
done_ok(){
touch /var/log/init-ok
cat << EOF
+-------------------------------------------------+
|               optimizer is done                 |
|             Please Reboot system                |
|             Now SSH Port is :  66               |
+-------------------------------------------------+
EOF
}

# main
main(){
    yum_update
    zone_time
    limits_config
    sysctl_config
    LANG_config
    selinux_config
    log_config
    tmout_config
    firewalld_config
    sshd_config
    ipv6_config
    history_config
    service_config
    vim_config
    userpwd_config
    fail2ban_config
    done_ok
}
main
