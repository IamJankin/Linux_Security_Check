#!/bin/bash
# Linux Security Check
# Compatible system: CentOS6
# Author:Jankin

# 配置区：
# 管理员账号
username="superuser"

# ssh端口
ssh_port="1024"

#程序区：
#shell color
red_color="\E[0;31m"
RED_color="\E[1;31m"
green_color="\E[0;32m"
GREEN_color="\E[1;32m"
yellow_color="\E[0;33m"
YELLOW_color="\E[1;33m"
blue_color="\E[0;34m"
BLUE_color="\E[1;34m"
default_color="\E[0m"

check_status="${yellow_color}[*]${default_color}"
CHECK_status="${YELLOW_color}[*]${default_color}"
finish_status="${blue_color}[*]${default_color}"
FINISH_status="${BLUE_color}[*]${default_color}"
correct_status="${green_color}[+]${default_color}"
CORRECT_status="${GREEN_color}[+]${default_color}"
error_status="${red_color}[-]${default_color}"
ERROR_status="${RED_color}[-]${default_color}"

echo -e "${CHECK_status} 开始进行Linux安全基线检测...\n"

# 输出当前Linux信息
echo -e "${FINISH_status} 当前Linux信息："
current_user=`whoami`
echo "主机名：`hostname`"
echo "当前用户：${current_user}"
echo -e "当前IP：`/sbin/ifconfig | grep 'inet addr' | sed 's/^.*addr://' | sed 's/ Bcast.*$//' | sed '/127.*/d'`\n"

# 判断是否为root
if [ $current_user != 'root' ]
then
	echo -e "${ERROR_status} 请使用root用户执行脚本！"
	exit 123
fi

# 检测函数，下面的程序使用grep去检测，check()函数则通过$?返回状态判断是否符合条件
function check(){
	if [ $? == 0 ]
	then
		echo -e "${correct_status} $1符合要求"
	else
		echo -e "${error_status} $1不符合要求"
	fi
}

# 账号口令检测
echo -e "${CHECK_status} 正在进行账号口令检测..."

# 1、口令复杂度
grep '^password\s\+requisite\s\+pam_cracklib.so\s\+.*minlen=8' /etc/pam.d/system-auth-ac | grep 'minclass=3' > /dev/null
check 口令复杂度

# 2、口令生存周期
grep '^PASS_MAX_DAYS\s\+90' /etc/login.defs > /dev/null
check 口令生存周期
chage -l root | grep 'Maximum number of days between password change\s\+:\s\+90' > /dev/null
check root用户口令生存周期
echo -e "${FINISH_status} 已完成账号口令检测"
echo  "----------------------------------"

# 权限检测
echo -e "${CHECK_status} 正在进行权限检测..."
# 检查/etc/passwd、/etc/group、/etc/profile文件所属者、所有组是否为root，权限是否为644
for f in /etc/passwd /etc/group /etc/profile
do
	 ls -l ${f} | grep 'root root' | grep 'rw-r--r--' > /dev/null
	check ${f}文件权限
done
# 检查/etc/shadow、/etc/gshadow文件所属者、所有组是否为root，权限是否为000
for f in /etc/shadow /etc/gshadow
do
	 ls -l ${f} | grep 'root root' | grep -- "---------" > /dev/null
	check ${f}文件权限
done
# 检查/tmp目录所属者、所有组是否为root，权限是否为750
ls -ld /tmp/ | grep 'root root' | grep 'rwxr-x---' > /dev/null
check /tmp目录权限
# 检查/var/log/目录所属者、所有组是否为root，权限是否为740
ls -ld /var/log/ | grep 'root root' | grep 'rwxr-----' > /dev/null
check /var/log目录权限
# 检查/boot/grub/grub.conf文件所属者、所有组是否为root，权限是否为600
ls -l /boot/grub/grub.conf | grep 'root root' | grep 'rw-------' > /dev/null
check /boot/grub/grub.conf文件权限
echo -e "${FINISH_status} 已完成权限检测"
echo  "----------------------------------"

# 日志审计检测
echo -e "${CHECK_status} 正在进行日志审计服务检测..."
service rsyslog status > /dev/null
check "rsyslog 服务状态"
service auditd status > /dev/null
check "auditd 服务状态"
echo -e "${FINISH_status} 已完成日志审计服务检测"
echo  "----------------------------------"

# 协议安全检测
echo -e "${CHECK_status} 正在进行协议安全检测..."
# 协议安全检测_SSH检测
echo -e "${check_status} 正在检测SSH协议..."
grep "^Port $ssh_port" /etc/ssh/sshd_config > /dev/null
check SSH端口号
grep "^Protocol 2" /etc/ssh/sshd_config > /dev/null
check SSH安全协议
grep "^PermitEmptyPasswords no" /etc/ssh/sshd_config > /dev/null
check SSH空密码限制
grep "^PermitRootLogin no" /etc/ssh/sshd_config > /dev/null
check SSH禁止root登录
grep "^MaxAuthTries 5" /etc/ssh/sshd_config > /dev/null
check SSH登录失败次数限制
grep "^ClientAliveInterval 600" /etc/ssh/sshd_config > /dev/null
check SSH超时退出登录参数ClientAliveInterval配置
grep "^ClientAliveCountMax 0" /etc/ssh/sshd_config > /dev/null
check SSH超时退出登录参数ClientAliveCountMax配置
grep "^LogLevel INFO" /etc/ssh/sshd_config > /dev/null
check SSH日志级别配置
echo -e "${FINISH_status} 已完成协议安全检测"
echo  "----------------------------------"

# 系统安全检测
# 1、限制用户su到root，仅允许管理员账号su到root
echo -e "${CHECK_status} 正在进行系统安全检测..."
grep "^wheel.*${username}" /etc/group > /dev/null
check ${username}加入到wheel组
grep "^auth\s\+required\s\+pam_wheel.so" /etc/pam.d/su > /dev/null
check /etc/pam.d/su文件配置
grep "^SU_WHEEL_ONLY yes" /etc/login.defs > /dev/null
check /etc/login.defs文件SU_WHEEL_ONLY参数配置
echo -e "${finish_status} 限制用户su到root检测完毕"

# 2、GRUB加密
grep "password ${password}" /boot/grub/grub.conf > /dev/null
check GRUB加密
echo -e "${finish_status} GRUB加密检测完毕"
echo -e "${FINISH_status} 已完成系统安全检测"
echo  "----------------------------------"

echo -e "${FINISH_status} 已完成Linux安全基线检测"
