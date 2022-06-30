#!/bin/bash
# Linux Security Hardening
# Compatible system: CentOS6
# Author:Jankin

# 配置区：
# 管理员账号
username="superuser"
password="P@ssw0rd"

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

echo -e "${CHECK_status} 开始进行Linux安全基线加固...\n"

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

# 账号口令加固
echo -e "${CHECK_status} 正在进行账号口令加固..."
# 1、口令复杂度
# 备份/etc/pam.d/system-auth-ac
cp -p /etc/pam.d/system-auth-ac /etc/pam.d/system-auth-ac_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/password\s\+requisite\s\+pam_cracklib.so/{s/pam_cracklib.so .*/pam_cracklib.so try_first_pass retry=3 minlen=8 minclass=3/}' /etc/pam.d/system-auth-ac
echo -e "${finish_status} 已完成口令复杂度加固"

# 2、口令生存期
cp -p /etc/login.defs /etc/login.defs_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/^PASS_MAX_DAYS\s\+[0-9]*/{s/[0-9]\+/90/}' /etc/login.defs
sed -i '/^PASS_MIN_DAYS\s\+[0-9]*/{s/[0-9]\+/0/}' /etc/login.defs
sed -i '/^PASS_WARN_AGE\s\+[0-9]*/{s/[0-9]\+/7/}' /etc/login.defs
chage -M 90 root
echo -e "${finish_status} 已完成口令生存期加固"

echo -e "${FINISH_status} 已完成账号口令加固"
echo  "----------------------------------"

# 权限加固
echo -e "${CHECK_status} 正在进行权限加固..."
chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/profile /tmp /var/log/ /etc/grub.conf /boot/grub/grub.conf
chmod 644 /etc/passwd /etc/group /etc/profile
chmod 000 /etc/shadow /etc/gshadow
chmod 750 /tmp
chmod 740 /var/log/
chmod 600 /boot/grub/grub.conf
echo -e "${FINISH_status} 已完成权限加固"
echo  "----------------------------------"

# 日志审计服务加固
echo -e "${CHECK_status} 正在进行日志审计服务加固..."
# Server Check，用于检测服务是否正常运行，如果没有运行就
function serverCheck(){
	status=`service $1 status`
	echo ${status}|grep 'running' > /dev/null
	if [ $? == 0 ]		#如果running在返回值里，那么就会返回0，不在返回值里就会返回1
	then
		chkconfig $1 on
		echo -e "${correct_status} $1服务已运行"
	else
		echo -e "${error_status} $1服务未运行，正在重新启动..."
		chkconfig $1 on
		service $1 start
		if [ $? == 0 ]
		then
			echo -e "${correct_status} $1服务已成功启动。"
		else
			echo -e "${ERROR_status} $1服务无法启动，请手动排查问题。"
		fi
	fi
}
# 调用serverCheck函数进行加固
serverCheck rsyslog
serverCheck auditd
echo -e "${FINISH_status} 已完成日志审计服务加固"
echo  "----------------------------------"

# 协议安全加固
echo -e "${CHECK_status} 正在进行协议安全加固..."
# 协议安全加固_SSH加固
echo -e "${check_status} 正在加固SSH协议"
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_bak_$(date +%Y-%m-%d_%H:%M)
sed -i "s/.*Port\s\+[0-9]*/Port ${ssh_port}/" /etc/ssh/sshd_config
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssh_port} -j ACCEPT
service iptables save
echo -e "${correct_status} 已将SSH端口修改为：${ssh_port}"
sed -i 's/.*Protocol\s\+[0-9]*/Protocol 2/' /etc/ssh/sshd_config
echo -e "${correct_status} 已将SSH协议版本设为Protocol 2"
sed -i 's/.*PermitEmptyPasswords\s\+.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo -e "${correct_status} 已禁止空密码登录SSH"
sed -i 's/.*PermitRootLogin\s\+\(yes\|no\)/PermitRootLogin no/' /etc/ssh/sshd_config
echo -e "${correct_status} 已禁止root登录SSH"
sed -i 's/.*MaxAuthTries\s\+[0-9]\+/MaxAuthTries 5/' /etc/ssh/sshd_config
echo -e "${correct_status} SSH密码最大尝试失败次数为5次"
sed -i 's/.*ClientAliveInterval\s\+[0-9]\+/ClientAliveInterval 600/' /etc/ssh/sshd_config
sed -i 's/.*ClientAliveCountMax\s\+[0-9]\+/ClientAliveCountMax 0/' /etc/ssh/sshd_config
echo -e "${correct_status} 用户10分钟没有动作自动退出SSH"
sed -i 's/.*LogLevel\s\+.\+/LogLevel INFO/' /etc/ssh/sshd_config
echo -e "${correct_status} SSH日志等级为INFO级别"
service sshd restart
echo -e "${FINISH_status} 已完成协议安全加固"
echo  "----------------------------------"


# 系统安全加固
echo -e "${CHECK_status} 正在进行系统安全加固..."
# 1、限制用户su到root，仅允许管理员账号su到root
# (1)创建管理员账号
useradd -G wheel ${username}
echo -e "${correct_status} 已创建管理员用户：${username}"
echo ${password} | passwd --stdin ${username}
# (2)备份/etc/pam.d/su，并修改su文件
cp -p /etc/pam.d/su /etc/pam.d/su_bak_$(date +%Y-%m-%d_%H:%M)
sed -i '/auth\s\+required\s\+pam_wheel.so/{s/^#//}' /etc/pam.d/su
# (3)备份/etc/login.defs，在文件底部新增“SU_WHEEL_ONLY yes”
cp -p /etc/login.defs /etc/login.defs_bak_$(date +%Y-%m-%d_%H:%M)
wheel_info=`grep 'SU_WHEEL_ONLY' /etc/login.defs`
if [ $? == 0 ]
then
	sed -i 's/SU_WHEEL_ONLY\s\+.*/SU_WHEEL_ONLY yes/' /etc/login.defs
else
	echo "SU_WHEEL_ONLY yes" >> /etc/login.defs
fi
echo -e "${correct_status} 已禁止普通用户su到root，仅允许管理员账号[${username}]su到root"

# 2、GRUB加密
cp -p /boot/grub/grub.conf /boot/grub/grub.conf_bak_$(date +%Y-%m-%d_%H:%M)
grub_passwd=`grep "password" /boot/grub/grub.conf`
if [ $? == 0 ]
then    
	echo -e "${check_status} GRUB文件已存在password信息：`echo ${grub_passwd} | sed 's/password\s\+//'`，正在替换为${password}"
	sed -i "s/^password\s\+.*/password ${password}/" /boot/grub/grub.conf
else
	sed -i "/^title/ipassword ${password}" /boot/grub/grub.conf
fi
echo -e "${finish_status} 已完成GRUB加密，GRUB密码已设为${password}"
echo -e "${FINISH_status} 已完成系统安全加固"
echo  "----------------------------------"

echo -e "${FINISH_status} 已完成Linux安全基线加固"
