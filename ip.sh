#!/bin/bash
script_version="v2025-07-13"
check_bash(){
current_bash_version=$(bash --version|head -n 1|awk -F ' ' '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) {print $i; exit}}'|cut -d . -f 1)
if [ "$current_bash_version" = "0" ]||[ "$current_bash_version" = "1" ]||[ "$current_bash_version" = "2" ]||[ "$current_bash_version" = "3" ];then
echo "ERROR: Bash version is lower than 4.0!"
echo "Tips: Run the following script to automatically upgrade Bash."
echo "bash <(curl -sL https://raw.githubusercontent.com/xykt/IPQuality/main/ref/upgrade_bash.sh)"
exit 0
fi
}
check_bash
Font_B="\033[1m"
Font_D="\033[2m"
Font_I="\033[3m"
Font_U="\033[4m"
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_Cyan="\033[36m"
Font_White="\033[37m"
Back_Black="\033[40m"
Back_Red="\033[41m"
Back_Green="\033[42m"
Back_Yellow="\033[43m"
Back_Blue="\033[44m"
Back_Purple="\033[45m"
Back_Cyan="\033[46m"
Back_White="\033[47m"
Font_Suffix="\033[0m"
Font_LineClear="\033[2K"
Font_LineUp="\033[1A"
declare ADLines
declare -A aad
declare IP=""
declare IPhide
declare fullIP=0
declare YY="cn"
declare -A maxmind
declare -A ipinfo
declare -A scamalytics
declare -A ipregistry
declare -A ipapi
declare -A abuseipdb
declare -A ip2location
declare -A dbip
declare -A ipwhois
declare -A ipdata
declare -A ipqs
declare -A cloudflare
declare -A tiktok
declare -A disney
declare -A netflix
declare -A youtube
declare -A amazon
declare -A spotify
declare -A chatgpt
declare IPV4
declare IPV6
declare IPV4check=1
declare IPV6check=1
declare IPV4work=0
declare IPV6work=0
declare ERRORcode=0
declare shelp
declare -A swarn
declare -A sinfo
declare -A shead
declare -A sbasic
declare -A stype
declare -A sscore
declare -A sfactor
declare -A smedia
declare -A smailstatus
declare -A stail
declare mode_no=0
declare mode_yes=0
declare mode_lite=0
declare mode_json=0
declare mode_menu=0
declare mode_output=0
declare ipjson
declare ibar=0
declare bar_pid
declare ibar_step=0
declare main_pid=$$
declare PADDING=""
declare useNIC=""
declare usePROXY=""
declare CurlARG=""
declare UA_Browser
declare rawgithub
declare Media_Cookie
declare IATA_Database
shelp_lines=(
"IP QUALITY CHECK SCRIPT IP质量体检脚本"
"Interactive Interface:  bash <(curl -sL IP.Check.Place) -EM"
"交互界面：              bash <(curl -sL IP.Check.Place) -M"
"Parameters 参数运行: bash <(curl -sL IP.Check.Place) [-4] [-6] [-f] [-h] [-j] [-i iface] [-l language] [-n] [-x proxy] [-y] [-E] [-M]"
"            -4                             Test IPv4                                  测试IPv4"
"            -6                             Test IPv6                                  测试IPv6"
"            -f                             Show full IP on reports                    报告展示完整IP地址"
"            -h                             Help information                           帮助信息"
"            -j                             JSON output                                JSON输出"
"            -i eth0                        Specify network interface                  指定检测网卡"
"               ipaddress                   Specify outbound IP Address                指定检测出口IP"
"            -l cn|en|jp|es|de|fr|ru|pt     Specify script language                    指定报告语言"
"            -n                             No OS or dependencies check                跳过系统检测及依赖安装"
"            -o /path/to/file.ansi          Output ANSI report to file                 输出ANSI报告至文件"
"               /path/to/file.json          Output JSON result to file                 输出JSON结果至文件"
"               /path/to/file.anyother      Output plain text report to file           输出纯文本报告至文件"
"            -x http://usr:pwd@proxyurl:p   Specify http proxy                         指定http代理"
"               https://usr:pwd@proxyurl:p  Specify https proxy                        指定https代理"
"               socks5://usr:pwd@proxyurl:p Specify socks5 proxy                       指定socks5代理"
"            -y                             Install dependencies without interupt      自动安装依赖"
"            -E                             Specify English Output                     指定英文输出"
"            -M                             Run with Interactive Interface             交互界面方式运行")
shelp=$(printf "%s\n" "${shelp_lines[@]}")
set_language(){
case "$YY" in
"en"|"jp"|"es"|"de"|"fr"|"ru"|"pt")swarn[1]="ERROR: Unsupported parameters!"
swarn[2]="ERROR: IP address format error!"
swarn[3]="ERROR: Dependent programs are missing. Please run as root or install sudo!"
swarn[4]="ERROR: Parameter -4 conflicts with -i or -6!"
swarn[6]="ERROR: Parameter -6 conflicts with -i or -4!"
swarn[7]="ERROR: The specified network interface or outbound IP is invalid or does not exist!"
swarn[8]="ERROR: The specified proxy parameter is invalid or not working!"
swarn[10]="ERROR: Output file already exist!"
swarn[11]="ERROR: Output file is not writable!"
swarn[40]="ERROR: IPv4 is not available!"
swarn[60]="ERROR: IPv6 is not available!"
sinfo[database]="Checking IP database "
sinfo[media]="Checking stream media "
sinfo[ai]="Checking AI provider "
sinfo[ldatabase]=21
sinfo[lmedia]=22
sinfo[lai]=21
shead[title]="IP QUALITY CHECK REPORT: "
shead[title_lite]="IP QUALITY CHECK REPORT(LITE): "
shead[ver]="Version: $script_version"
shead[bash]="bash <(curl -sL Check.Place) -EI"
shead[git]="https://github.com/xykt/IPQuality"
shead[time]=$(date -u +"Report Time: %Y-%m-%d %H:%M:%S UTC")
shead[ltitle]=25
shead[ltitle_lite]=31
shead[ptime]=$(printf '%7s' '')
sbasic[title]="1. Basic Information (${Font_I}Maxmind Database$Font_Suffix)"
sbasic[title_lite]="1. Basic Information (${Font_I}IPinfo Database$Font_Suffix)"
sbasic[asn]="ASN:                    "
sbasic[noasn]="Not Assigned"
sbasic[org]="Organization:           "
sbasic[location]="Location:               "
sbasic[map]="Map:                    "
sbasic[city]="City:                   "
sbasic[country]="Actual Region:          "
sbasic[regcountry]="Registered Region:      "
sbasic[continent]="Continent:              "
sbasic[timezone]="Time Zone:              "
sbasic[type]="IP Type:                "
sbasic[type0]=" Geo-consistent "
sbasic[type1]=" Geo-discrepant "
stype[business]=" $Back_Yellow$Font_White$Font_B Business $Font_Suffix "
stype[isp]="   $Back_Green$Font_White$Font_B ISP $Font_Suffix    "
stype[hosting]=" $Back_Red$Font_White$Font_B Hosting $Font_Suffix  "
stype[education]="$Back_Yellow$Font_White$Font_B Education $Font_Suffix "
stype[government]="$Back_Yellow$Font_White$Font_B Government $Font_Suffix"
stype[banking]=" $Back_Yellow$Font_White$Font_B Banking $Font_Suffix  "
stype[organization]="$Back_Yellow$Font_White${Font_B}Organization$Font_Suffix"
stype[military]=" $Back_Yellow$Font_White$Font_B Military $Font_Suffix "
stype[library]=" $Back_Yellow$Font_White$Font_B Library $Font_Suffix  "
stype[cdn]="   $Back_Red$Font_White$Font_B CDN $Font_Suffix    "
stype[lineisp]=" $Back_Green$Font_White$Font_B Line ISP $Font_Suffix "
stype[mobile]="$Back_Green$Font_White$Font_B Mobile ISP $Font_Suffix"
stype[spider]="$Back_Red$Font_White$Font_B Web Spider $Font_Suffix"
stype[reserved]=" $Back_Yellow$Font_White$Font_B Reserved $Font_Suffix "
stype[other]="  $Back_Yellow$Font_White$Font_B Other $Font_Suffix   "
stype[title]="2. IP Type"
stype[db]="Database:  "
stype[usetype]="Usage:     "
stype[comtype]="Company:   "
sscore[verylow]="$Font_Green${Font_B}VeryLow$Font_Suffix"
sscore[low]="$Font_Green${Font_B}Low$Font_Suffix"
sscore[medium]="$Font_Yellow${Font_B}Medium$Font_Suffix"
sscore[high]="$Font_Red${Font_B}High$Font_Suffix"
sscore[veryhigh]="$Font_Red${Font_B}VeryHigh$Font_Suffix"
sscore[elevated]="$Font_Yellow${Font_B}Elevated$Font_Suffix"
sscore[suspicious]="$Font_Yellow${Font_B}Suspicious$Font_Suffix"
sscore[risky]="$Font_Red${Font_B}Risky$Font_Suffix"
sscore[highrisk]="$Font_Red${Font_B}HighRisk$Font_Suffix"
sscore[dos]="$Font_Red${Font_B}DoS$Font_Suffix"
sscore[colon]=": "
sscore[title]="3. Risk Score"
sscore[range]="${Font_Cyan}Levels:         $Font_I$Font_White${Back_Green}VeryLow     Low $Back_Yellow     Medium     $Back_Red High   VeryHigh$Font_Suffix"
sfactor[title]="4. Risk Factors"
sfactor[factor]="DB:  "
sfactor[countrycode]="Region: "
sfactor[proxy]="Proxy:  "
sfactor[tor]="Tor:    "
sfactor[vpn]="VPN:    "
sfactor[server]="Server: "
sfactor[abuser]="Abuser: "
sfactor[robot]="Robot:  "
sfactor[yes]="$Font_Red$Font_B Yes$Font_Suffix"
sfactor[no]="$Font_Green$Font_B No $Font_Suffix"
sfactor[na]="$Font_Green$Font_B N/A$Font_Suffix"
smedia[yes]="  $Back_Green$Font_White Yes $Font_Suffix  "
smedia[no]=" $Back_Red$Font_White Block $Font_Suffix "
smedia[bad]="$Back_Red$Font_White Failed $Font_Suffix "
smedia[pending]="$Back_Yellow$Font_White Pending $Font_Suffix"
smedia[cn]=" $Back_Red$Font_White China $Font_Suffix "
smedia[noprem]="$Back_Red$Font_White NoPrem. $Font_Suffix"
smedia[org]="$Back_Yellow$Font_White NF.Only $Font_Suffix"
smedia[web]="$Back_Yellow$Font_White WebOnly $Font_Suffix"
smedia[app]="$Back_Yellow$Font_White APPOnly $Font_Suffix"
smedia[idc]="  $Back_Yellow$Font_White IDC $Font_Suffix  "
smedia[native]="$Back_Green$Font_White Native $Font_Suffix "
smedia[dns]="$Back_Yellow$Font_White ViaDNS $Font_Suffix "
smedia[nodata]="         "
smedia[title]="5. Accessibility check for media and AI services"
smedia[meida]="Service: "
smedia[status]="Status:  "
smedia[region]="Region:  "
smedia[type]="Type:    "
stail[stoday]="IP Checks Today: "
stail[stotal]="; Total: "
stail[thanks]=". Thanks for running xy scripts!"
stail[link]="${Font_I}Report Link: $Font_U"
;;
"cn")swarn[1]="错误：不支持的参数！"
swarn[2]="错误：IP地址格式错误！"
swarn[3]="错误：未安装依赖程序，请以root执行此脚本，或者安装sudo命令！"
swarn[4]="错误：参数-4与-i/-6冲突！"
swarn[6]="错误：参数-6与-i/-4冲突！"
swarn[7]="错误：指定的网卡或出口IP不存在！"
swarn[8]="错误：指定的代理服务器不可用！"
swarn[10]="错误：输出文件已存在！"
swarn[11]="错误：输出文件不可写！"
swarn[40]="错误：IPV4不可用！"
swarn[60]="错误：IPV6不可用！"
sinfo[database]="正在检测IP数据库 "
sinfo[media]="正在检测流媒体服务商 "
sinfo[ai]="正在检测AI服务商 "
sinfo[ldatabase]=17
sinfo[lmedia]=21
sinfo[lai]=17
shead[title]="IP质量体检报告："
shead[title_lite]="IP质量体检报告(Lite)："
shead[ver]="脚本版本：$script_version"
shead[bash]="bash <(curl -sL Check.Place) -I"
shead[git]="https://github.com/xykt/IPQuality"
shead[time]=$(TZ="Asia/Shanghai" date +"报告时间：%Y-%m-%d %H:%M:%S CST")
shead[ltitle]=16
shead[ltitle_lite]=22
shead[ptime]=$(printf '%8s' '')
sbasic[title]="一、基础信息（${Font_I}Maxmind 数据库$Font_Suffix）"
sbasic[title_lite]="一、基础信息（${Font_I}IPinfo 数据库$Font_Suffix）"
sbasic[asn]="自治系统号：            "
sbasic[noasn]="未分配"
sbasic[org]="组织：                  "
sbasic[location]="坐标：                  "
sbasic[map]="地图：                  "
sbasic[city]="城市：                  "
sbasic[country]="使用地：                "
sbasic[regcountry]="注册地：                "
sbasic[continent]="洲际：                  "
sbasic[timezone]="时区：                  "
sbasic[type]="IP类型：                "
sbasic[type0]=" 原生IP "
sbasic[type1]=" 广播IP "
stype[business]="   $Back_Yellow$Font_White$Font_B 商业 $Font_Suffix   "
stype[isp]="   $Back_Green$Font_White$Font_B 家宽 $Font_Suffix   "
stype[hosting]="   $Back_Red$Font_White$Font_B 机房 $Font_Suffix   "
stype[education]="   $Back_Yellow$Font_White$Font_B 教育 $Font_Suffix   "
stype[government]="   $Back_Yellow$Font_White$Font_B 政府 $Font_Suffix   "
stype[banking]="   $Back_Yellow$Font_White$Font_B 银行 $Font_Suffix   "
stype[organization]="   $Back_Yellow$Font_White$Font_B 组织 $Font_Suffix   "
stype[military]="   $Back_Yellow$Font_White$Font_B 军队 $Font_Suffix   "
stype[library]="  $Back_Yellow$Font_White$Font_B 图书馆 $Font_Suffix  "
stype[cdn]="   $Back_Red$Font_White$Font_B CDN $Font_Suffix    "
stype[lineisp]="   $Back_Green$Font_White$Font_B 家宽 $Font_Suffix   "
stype[mobile]="   $Back_Green$Font_White$Font_B 手机 $Font_Suffix   "
stype[spider]="   $Back_Red$Font_White$Font_B 蜘蛛 $Font_Suffix   "
stype[reserved]="   $Back_Yellow$Font_White$Font_B 保留 $Font_Suffix   "
stype[other]="   $Back_Yellow$Font_White$Font_B 其他 $Font_Suffix   "
stype[title]="二、IP类型属性"
stype[db]="数据库：   "
stype[usetype]="使用类型： "
stype[comtype]="公司类型： "
sscore[verylow]="$Font_Green$Font_B极低风险$Font_Suffix"
sscore[low]="$Font_Green$Font_B低风险$Font_Suffix"
sscore[medium]="$Font_Yellow$Font_B中风险$Font_Suffix"
sscore[high]="$Font_Red$Font_B高风险$Font_Suffix"
sscore[veryhigh]="$Font_Red$Font_B极高风险$Font_Suffix"
sscore[elevated]="$Font_Yellow$Font_B较高风险$Font_Suffix"
sscore[suspicious]="$Font_Yellow$Font_B可疑IP$Font_Suffix"
sscore[risky]="$Font_Red$Font_B存在风险$Font_Suffix"
sscore[highrisk]="$Font_Red$Font_B高风险$Font_Suffix"
sscore[dos]="$Font_Red$Font_B建议封禁$Font_Suffix"
sscore[colon]="："
sscore[title]="三、风险评分"
sscore[range]="$Font_Cyan风险等级：      $Font_I$Font_White$Back_Green极低         低 $Back_Yellow      中等      $Back_Red 高         极高$Font_Suffix"
sfactor[title]="四、风险因子"
sfactor[factor]="库： "
sfactor[countrycode]="地区：  "
sfactor[proxy]="代理：  "
sfactor[tor]="Tor：   "
sfactor[vpn]="VPN：   "
sfactor[server]="服务器："
sfactor[abuser]="滥用：  "
sfactor[robot]="机器人："
sfactor[yes]="$Font_Red$Font_B 是 $Font_Suffix"
sfactor[no]="$Font_Green$Font_B 否 $Font_Suffix"
sfactor[na]="$Font_Green$Font_B 无 $Font_Suffix"
smedia[yes]=" $Back_Green$Font_White 解锁 $Font_Suffix  "
smedia[no]=" $Back_Red$Font_White 屏蔽 $Font_Suffix  "
smedia[bad]=" $Back_Red$Font_White 失败 $Font_Suffix  "
smedia[pending]="$Back_Yellow$Font_White 待支持 $Font_Suffix "
smedia[cn]=" $Back_Red$Font_White 中国 $Font_Suffix  "
smedia[noprem]="$Back_Red$Font_White 禁会员 $Font_Suffix "
smedia[org]="$Back_Yellow$Font_White 仅自制 $Font_Suffix "
smedia[web]="$Back_Yellow$Font_White 仅网页 $Font_Suffix "
smedia[app]=" $Back_Yellow$Font_White 仅APP $Font_Suffix "
smedia[idc]=" $Back_Yellow$Font_White 机房 $Font_Suffix  "
smedia[native]=" $Back_Green$Font_White 原生 $Font_Suffix  "
smedia[dns]="  $Back_Yellow$Font_White DNS $Font_Suffix  "
smedia[nodata]="         "
smedia[title]="五、流媒体及AI服务解锁检测"
smedia[meida]="服务商： "
smedia[status]="状态：   "
smedia[region]="地区：   "
smedia[type]="方式：   "
stail[stoday]="今日IP检测量："
stail[stotal]="；总检测量："
stail[thanks]="。感谢使用xy系列脚本！"
stail[link]="$Font_I报告链接：$Font_U"
;;
*)echo -ne "ERROR: Language not supported!"
esac
}
countRunTimes(){
local RunTimes=$(curl $CurlARG -s --max-time 10 "https://hits.xykt.de/ip?action=hit" 2>&1)
stail[today]=$(echo "$RunTimes"|jq '.daily')
stail[total]=$(echo "$RunTimes"|jq '.total')
}
show_progress_bar(){
show_progress_bar_ "$@" 1>&2
}
show_progress_bar_(){
local bar="\u280B\u2819\u2839\u2838\u283C\u2834\u2826\u2827\u2807\u280F"
local n=${#bar}
while sleep 0.1;do
if ! kill -0 $main_pid 2>/dev/null;then
echo -ne ""
exit
fi
echo -ne "\r$Font_Cyan$Font_B[$IP]# $1$Font_Cyan$Font_B$(printf '%*s' "$2" ''|tr ' ' '.') ${bar:ibar++*6%n:6} $(printf '%02d%%' $ibar_step) $Font_Suffix"
done
}
kill_progress_bar(){
kill "$bar_pid" 2>/dev/null&&echo -ne "\r"
}
install_dependencies(){
if ! jq --version >/dev/null 2>&1||! curl --version >/dev/null 2>&1||! bc --version >/dev/null 2>&1||! nc -h >/dev/null 2>&1||! dig -v >/dev/null 2>&1;then
echo "Detecting operating system..."
if [ "$(uname)" == "Darwin" ];then
install_packages "brew" "brew install" "no_sudo"
elif [ -f /etc/os-release ];then
. /etc/os-release
if [ $(id -u) -ne 0 ]&&! command -v sudo >/dev/null 2>&1;then
ERRORcode=3
fi
case $ID in
ubuntu|debian|linuxmint)install_packages "apt" "apt-get install -y"
;;
rhel|centos|almalinux|rocky|anolis)if
[ "$(echo $VERSION_ID|cut -d '.' -f1)" -ge 8 ]
then
install_packages "dnf" "dnf install -y"
else
install_packages "yum" "yum install -y"
fi
;;
arch|manjaro)install_packages "pacman" "pacman -S --noconfirm"
;;
alpine)install_packages "apk" "apk add"
;;
fedora)install_packages "dnf" "dnf install -y"
;;
alinux)install_packages "yum" "yum install -y"
;;
suse|opensuse*)install_packages "zypper" "zypper install -y"
;;
void)install_packages "xbps" "xbps-install -Sy"
;;
*)echo "Unsupported distribution: $ID"
exit 1
esac
elif [ -n "$PREFIX" ];then
install_packages "pkg" "pkg install"
else
echo "Cannot detect distribution because /etc/os-release is missing."
exit 1
fi
fi
}
install_packages(){
local package_manager=$1
local install_command=$2
local no_sudo=$3
echo "Using package manager: $package_manager"
echo -e "Lacking necessary dependencies, $Font_I${Font_Cyan}jq curl bc netcat dnsutils iproute$Font_Suffix will be installed using $Font_I$Font_Cyan$package_manager$Font_Suffix."
if [[ $mode_yes -eq 0 ]];then
prompt=$(printf "Continue? (${Font_Green}y$Font_Suffix/${Font_Red}n$Font_Suffix): ")
read -p "$prompt" choice
case "$choice" in
y|Y|yes|Yes|YES)echo "Continue to execute script..."
;;
n|N|no|No|NO)echo "Script exited."
exit 0
;;
*)echo "Invalid input, script exited."
exit 1
esac
else
echo -e "Detected parameter $Font_Green-y$Font_Suffix. Continue installation..."
fi
if [ "$no_sudo" == "no_sudo" ]||[ $(id -u) -eq 0 ];then
local usesudo=""
else
local usesudo="sudo"
fi
case $package_manager in
apt)$usesudo apt update
$usesudo $install_command jq curl bc netcat-openbsd dnsutils iproute2
;;
dnf|yum)$usesudo $install_command epel-release
$usesudo $package_manager makecache
$usesudo $install_command jq curl bc nmap-ncat bind-utils iproute
;;
pacman)$usesudo pacman -Sy
$usesudo $install_command jq curl bc gnu-netcat bind-tools iproute2
;;
apk)$usesudo apk update
$usesudo $install_command jq curl bc netcat-openbsd grep bind-tools iproute2
;;
pkg)$usesudo $package_manager update
$usesudo $package_manager $install_command jq curl bc netcat dnsutils iproute
;;
brew)eval "$(/opt/homebrew/bin/brew shellenv)"
$install_command jq curl bc netcat bind
;;
zypper)$usesudo zypper refresh
$usesudo $install_command jq curl bc netcat bind-utils iproute2
;;
xbps)$usesudo xbps-install -Sy
$usesudo $install_command jq curl bc netcat bind-utils iproute2
esac
}
declare -A browsers=(
[Chrome]="120.0.6087.129 121.0.6167.85 122.0.6261.39 123.0.6312.58 124.0.6367.91 125.0.6422.78"
[Firefox]="120.0.1 121.0.2 122.0.3 123.0.4 124.0.5 125.0.6")
declare -a edge_versions=(
"120.0.2210.91|120.0.6087.129"
"121.0.2277.83|121.0.6167.85"
"122.0.2345.29|122.0.6261.39"
"123.0.2403.130|123.0.6312.58"
"124.0.2478.51|124.0.6367.91"
"125.0.2535.67|125.0.6422.78")
generate_random_user_agent(){
local browsers_keys=(${!browsers[@]} "Edge")
local random_browser_index=$((RANDOM%${#browsers_keys[@]}))
local browser=${browsers_keys[random_browser_index]}
case $browser in
Chrome)local versions=(${browsers[Chrome]})
local version=${versions[RANDOM%${#versions[@]}]}
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$version Safari/537.36"
;;
Firefox)local versions=(${browsers[Firefox]})
local version=${versions[RANDOM%${#versions[@]}]}
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${version%%.*}) Gecko/20100101 Firefox/$version"
;;
Edge)local pair=${edge_versions[RANDOM%${#edge_versions[@]}]}
local edge_ver=${pair%%|*}
local chrome_ver=${pair##*|}
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$chrome_ver Safari/537.36 Edg/$edge_ver"
esac
}
adapt_locale(){
local ifunicode=$(printf '\\u2800')
[[ ${#ifunicode} -gt 3 ]]&&export LC_CTYPE=en_US.UTF-8 2>/dev/null
}
check_connectivity(){
local url="https://www.google.com/generate_204"
local timeout=2
local http_code
http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$timeout" "$url" 2>/dev/null)
if [[ $http_code == "204" ]];then
rawgithub="https://github.com/xykt/IPQuality/raw/"
return 0
else
rawgithub="https://testingcf.jsdelivr.net/gh/xykt/IPQuality@"
return 1
fi
}
is_valid_ipv4(){
local ip=$1
if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]];then
IFS='.' read -r -a octets <<<"$ip"
for octet in "${octets[@]}";do
if ((octet<0||octet>255));then
IPV4work=0
return 1
fi
done
IPV4work=1
return 0
else
IPV4work=0
return 1
fi
}
is_private_ipv4(){
local ip_address=$1
if [[ -z $ip_address ]];then
return 0
fi
if [[ $ip_address =~ ^10\. ]]||[[ $ip_address =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]||[[ $ip_address =~ ^192\.168\. ]]||[[ $ip_address =~ ^127\. ]]||[[ $ip_address =~ ^0\. ]]||[[ $ip_address =~ ^22[4-9]\. ]]||[[ $ip_address =~ ^23[0-9]\. ]];then
return 0
fi
return 1
}
get_ipv4(){
local response
IPV4=""
local API_NET=("myip.check.place" "ip.sb" "ping0.cc" "icanhazip.com" "api64.ipify.org" "ifconfig.co" "ident.me")
for p in "${API_NET[@]}";do
response=$(curl $CurlARG -s4 --max-time 2 "$p")
if [[ $? -eq 0 && ! $response =~ error && -n $response ]];then
IPV4="$response"
break
fi
done
}
hide_ipv4(){
if [[ -n $1 ]];then
IFS='.' read -r -a ip_parts <<<"$1"
IPhide="${ip_parts[0]}.${ip_parts[1]}.*.*"
else
IPhide=""
fi
}
is_valid_ipv6(){
local ip=$1
if [[ $ip =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,7}:$ || $ip =~ ^:([0-9a-fA-F]{1,4}:){1,7}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$ || $ip =~ ^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$ || $ip =~ ^:((:[0-9a-fA-F]{1,4}){1,7}|:)$ || $ip =~ ^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$ || $ip =~ ^::(ffff(:0{1,4}){0,1}:){0,1}(([0-9]{1,3}\.){3}[0-9]{1,3})$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,4}:(([0-9]{1,3}\.){3}[0-9]{1,3})$ ]];then
IPV6work=1
return 0
else
IPV6work=0
return 1
fi
}
is_private_ipv6(){
local address=$1
if [[ -z $address ]];then
return 0
fi
if [[ $address =~ ^fe80: ]]||[[ $address =~ ^fc00: ]]||[[ $address =~ ^fd00: ]]||[[ $address =~ ^2001:db8: ]]||[[ $address == ::1 ]]||[[ $address =~ ^::ffff: ]]||[[ $address =~ ^2002: ]]||[[ $address =~ ^2001: ]];then
return 0
fi
return 1
}
get_ipv6(){
local response
IPV6=""
local API_NET=("myip.check.place" "ip.sb" "ping0.cc" "icanhazip.com" "api64.ipify.org" "ifconfig.co" "ident.me")
for p in "${API_NET[@]}";do
response=$(curl $CurlARG -s6k --max-time 2 "$p")
if [[ $? -eq 0 && ! $response =~ error && -n $response ]];then
IPV6="$response"
break
}
hide_ipv6(){
if [[ -n $1 ]];then
local expanded_ip=$(echo "$1"|sed 's/::/:0000:0000:0000:0000:0000:0000:0000:0000:/g'|cut -d ':' -f1-8)
IFS=':' read -r -a ip_parts <<<"$expanded_ip"
while [ ${#ip_parts[@]} -lt 8 ];do
ip_parts+=(0000)
done
IPhide="${ip_parts[0]:-0}:${ip_parts[1]:-0}:${ip_parts[2]:-0}:*:*:*:*:*"
IPhide=$(echo "$IPhide"|sed 's/:0\{1,\}/:/g'|sed 's/::\+/:/g')
else
IPhide=""
fi
}
calculate_display_width(){
local string="$1"
local length=0
local char
for ((i=0; i<${#string}; i++));do
char=$(echo "$string"|od -An -N1 -tx1 -j $((i))|tr -d ' ')
if [ "$(printf '%d\n' 0x$char)" -gt 127 ];then
length=$((length+2))
i=$((i+1))
else
length=$((length+1))
fi
done
echo "$length"
}
calc_padding(){
local input_text="$1"
local total_width=$2
local title_length=$(calculate_display_width "$input_text")
local left_padding=$(((total_width-title_length)/2))
if [[ $left_padding -gt 0 ]];then
PADDING=$(printf '%*s' $left_padding)
else
PADDING=""
fi
}
generate_dms(){
local lat=$1
local lon=$2
if [[ -z $lat || $lat == "null" || -z $lon || $lon == "null" ]];then
echo ""
return
fi
convert_single(){
local coord=$1
local direction=$2
local fixed_coord=$(echo "$coord"|sed 's/\.$/.0/')
local degrees=$(echo "$fixed_coord"|cut -d'.' -f1)
local fractional="0.$(echo "$fixed_coord"|cut -d'.' -f2)"
local minutes=$(echo "$fractional * 60"|bc -l|cut -d'.' -f1)
local seconds_fractional="0.$(echo "$fractional * 60"|bc -l|cut -d'.' -f2)"
local seconds=$(echo "$seconds_fractional * 60"|bc -l|awk '{printf "%.0f", $1}')
echo "$degrees°$minutes′$seconds″$direction"
}
local lat_dir='N'
if [[ $(echo "$lat < 0"|bc -l) -eq 1 ]];then
lat_dir='S'
lat=$(echo "$lat * -1"|bc -l)
fi
local lon_dir='E'
if [[ $(echo "$lon < 0"|bc -l) -eq 1 ]];then
lon_dir='W'
lon=$(echo "$lon * -1"|bc -l)
fi
local lat_dms=$(convert_single $lat $lat_dir)
local lon_dms=$(convert_single $lon $lon_dir)
echo "$lon_dms, $lat_dms"
}
generate_googlemap_url(){
local lat=$1
local lon=$2
local radius=$3
if [[ -z $lat || $lat == "null" || -z $lon || $lon == "null" || -z $radius || $radius == "null" ]];then
echo ""
return
fi
local zoom_level=15
if [[ $radius -gt 1000 ]];then
zoom_level=12
elif [[ $radius -gt 500 ]];then
zoom_level=13
elif [[ $radius -gt 250 ]];then
zoom_level=14
fi
echo "https://check.place/$lat,$lon,$zoom_level,$YY"
}
db_maxmind(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}Maxmind $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-8-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
maxmind=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://ipinfo.check.place/$IP?lang=$YY")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
mode_lite=1
else
mode_lite=0
fi
maxmind[asn]=$(echo "$RESPONSE"|jq -r '.ASN.AutonomousSystemNumber')
maxmind[org]=$(echo "$RESPONSE"|jq -r '.ASN.AutonomousSystemOrganization')
maxmind[city]=$(echo "$RESPONSE"|jq -r '.City.Name')
maxmind[post]=$(echo "$RESPONSE"|jq -r '.City.PostalCode')
maxmind[lat]=$(echo "$RESPONSE"|jq -r '.City.Latitude')
maxmind[lon]=$(echo "$RESPONSE"|jq -r '.City.Longitude')
maxmind[rad]=$(echo "$RESPONSE"|jq -r '.City.AccuracyRadius')
maxmind[continentcode]=$(echo "$RESPONSE"|jq -r '.City.Continent.Code')
maxmind[continent]=$(echo "$RESPONSE"|jq -r '.City.Continent.Name')
maxmind[citycountrycode]=$(echo "$RESPONSE"|jq -r '.City.Country.IsoCode')
maxmind[citycountry]=$(echo "$RESPONSE"|jq -r '.City.Country.Name')
maxmind[timezone]=$(echo "$RESPONSE"|jq -r '.City.Location.TimeZone')
maxmind[subcode]=$(echo "$RESPONSE"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].IsoCode else "N/A" end')
maxmind[sub]=$(echo "$RESPONSE"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].Name else "N/A" end')
maxmind[countrycode]=$(echo "$RESPONSE"|jq -r '.Country.IsoCode')
maxmind[country]=$(echo "$RESPONSE"|jq -r '.Country.Name')
maxmind[regcountrycode]=$(echo "$RESPONSE"|jq -r '.Country.RegisteredCountry.IsoCode')
maxmind[regcountry]=$(echo "$RESPONSE"|jq -r '.Country.RegisteredCountry.Name')
if [[ $YY != "en" ]];then
local backup_response=$(curl $CurlARG -s -$1 -m 10 "http://ipinfo.check.place/$IP?lang=en")
[[ ${maxmind[asn]} == "null" ]]&&maxmind[asn]=$(echo "$backup_response"|jq -r '.ASN.AutonomousSystemNumber')
[[ ${maxmind[org]} == "null" ]]&&maxmind[org]=$(echo "$backup_response"|jq -r '.ASN.AutonomousSystemOrganization')
[[ ${maxmind[city]} == "null" ]]&&maxmind[city]=$(echo "$backup_response"|jq -r '.City.Name')
[[ ${maxmind[post]} == "null" ]]&&maxmind[post]=$(echo "$backup_response"|jq -r '.City.PostalCode')
[[ ${maxmind[lat]} == "null" ]]&&maxmind[lat]=$(echo "$backup_response"|jq -r '.City.Latitude')
[[ ${maxmind[lon]} == "null" ]]&&maxmind[lon]=$(echo "$backup_response"|jq -r '.City.Longitude')
[[ ${maxmind[rad]} == "null" ]]&&maxmind[rad]=$(echo "$backup_response"|jq -r '.City.AccuracyRadius')
[[ ${maxmind[continentcode]} == "null" ]]&&maxmind[continentcode]=$(echo "$backup_response"|jq -r '.City.Continent.Code')
[[ ${maxmind[continent]} == "null" ]]&&maxmind[continent]=$(echo "$backup_response"|jq -r '.City.Continent.Name')
[[ ${maxmind[citycountrycode]} == "null" ]]&&maxmind[citycountrycode]=$(echo "$backup_response"|jq -r '.City.Country.IsoCode')
[[ ${maxmind[citycountry]} == "null" ]]&&maxmind[citycountry]=$(echo "$backup_response"|jq -r '.City.Country.Name')
[[ ${maxmind[timezone]} == "null" ]]&&maxmind[timezone]=$(echo "$backup_response"|jq -r '.City.Location.TimeZone')
[[ ${maxmind[subcode]} == "null" ]]&&maxmind[subcode]=$(echo "$backup_response"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].IsoCode else "N/A" end')
[[ ${maxmind[sub]} == "null" ]]&&maxmind[sub]=$(echo "$backup_response"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].Name else "N/A" end')
[[ ${maxmind[countrycode]} == "null" ]]&&maxmind[countrycode]=$(echo "$backup_response"|jq -r '.Country.IsoCode')
[[ ${maxmind[country]} == "null" ]]&&maxmind[country]=$(echo "$backup_response"|jq -r '.Country.Name')
[[ ${maxmind[regcountrycode]} == "null" ]]&&maxmind[regcountrycode]=$(echo "$backup_response"|jq -r '.Country.RegisteredCountry.IsoCode')
[[ ${maxmind[regcountry]} == "null" ]]&&maxmind[regcountry]=$(echo "$backup_response"|jq -r '.Country.RegisteredCountry.Name')
fi
if [[ ${maxmind[lat]} != "null" && ${maxmind[lon]} != "null" ]];then
maxmind[dms]=$(generate_dms "${maxmind[lat]}" "${maxmind[lon]}")
maxmind[map]=$(generate_googlemap_url "${maxmind[lat]}" "${maxmind[lon]}" "${maxmind[rad]}")
else
maxmind[dms]="null"
maxmind[map]="null"
fi
}
db_ipinfo(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPinfo $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-7-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipinfo=()
local RESPONSE=$(curl $CurlARG -Ls -m 10 "https://ipinfo.io/widget/api/ip/$IP" -H "Referer: https://ipinfo.io")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipinfo[status]="null"
else
ipinfo[status]=$(echo "$RESPONSE"|jq -r '.status')
ipinfo[asn]=$(echo "$RESPONSE"|jq -r '.asn')
ipinfo[org]=$(echo "$RESPONSE"|jq -r '.org')
ipinfo[countrycode]=$(echo "$RESPONSE"|jq -r '.country')
ipinfo[country]=$(echo "$RESPONSE"|jq -r '.country_name')
ipinfo[city]=$(echo "$RESPONSE"|jq -r '.city')
ipinfo[regioncode]=$(echo "$RESPONSE"|jq -r '.region')
ipinfo[region]=$(echo "$RESPONSE"|jq -r '.region_name')
ipinfo[post]=$(echo "$RESPONSE"|jq -r '.postal')
ipinfo[timezone]=$(echo "$RESPONSE"|jq -r '.timezone')
ipinfo[lat]=$(echo "$RESPONSE"|jq -r '.latitude')
ipinfo[lon]=$(echo "$RESPONSE"|jq -r '.longitude')
ipinfo[abusecontact]=$(echo "$RESPONSE"|jq -r '.abuse.email')
if [[ ${ipinfo[lat]} != "null" && ${ipinfo[lon]} != "null" ]];then
ipinfo[dms]=$(generate_dms "${ipinfo[lat]}" "${ipinfo[lon]}")
fi
fi
}
db_ipregistry(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPRegistry $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-10-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipregistry=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://api.ipregistry.co/$IP?key=tryout")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipregistry[status]="null"
else
ipregistry[status]=$(echo "$RESPONSE"|jq -r '.message')
ipregistry[companytype]=$(echo "$RESPONSE"|jq -r '.company.type')
ipregistry[connectiontype]=$(echo "$RESPONSE"|jq -r '.connection.type')
fi
}
db_ipapi(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IP-API $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-8-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipapi=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "http://ip-api.com/json/$IP?lang=$YY&fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipapi[status]="null"
else
ipapi[status]=$(echo "$RESPONSE"|jq -r '.status')
ipapi[proxy]=$(echo "$RESPONSE"|jq -r '.proxy')
ipapi[hosting]=$(echo "$RESPONSE"|jq -r '.hosting')
ipapi[mobile]=$(echo "$RESPONSE"|jq -r '.mobile')
fi
}
db_abuseipdb(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}AbuseIPDB $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-11-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
abuseipdb=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90&verbose=" -H "Key: dE1fMvY5oQ7zP3aS9cN2vB4xJ8hL6tG0" -H "Accept: application/json")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
abuseipdb[status]="null"
else
abuseipdb[status]=$(echo "$RESPONSE"|jq -r '.errors[0].detail')
abuseipdb[score]=$(echo "$RESPONSE"|jq -r '.data.abuseConfidenceScore')
abuseipdb[usage]=$(echo "$RESPONSE"|jq -r '.data.usageType')
abuseipdb[totalreports]=$(echo "$RESPONSE"|jq -r '.data.totalReports')
abuseipdb[lastreported]=$(echo "$RESPONSE"|jq -r '.data.lastReportedAt')
fi
}
db_ip2location(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IP2Location $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-11-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ip2location=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://api.ip2location.com/v2/?ip=$IP&key=demo&package=WS11&addon=usagetype,category&format=json")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ip2location[status]="null"
else
ip2location[status]=$(echo "$RESPONSE"|jq -r '.response')
ip2location[usagetype]=$(echo "$RESPONSE"|jq -r '.usage_type')
ip2location[category]=$(echo "$RESPONSE"|jq -r '.category')
fi
}
db_dbip(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}DB-IP $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-7-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
dbip=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://api.db-ip.com/v2/free/$IP")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
dbip[status]="null"
else
dbip[status]=$(echo "$RESPONSE"|jq -r '.error')
dbip[organization]=$(echo "$RESPONSE"|jq -r '.organization')
dbip[usagetype]=$(echo "$RESPONSE"|jq -r '.usageType')
fi
}
db_ipwhois(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPWhois $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-9-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipwhois=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://ipwhois.app/json/$IP?lang=$YY")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipwhois[status]="null"
else
ipwhois[status]=$(echo "$RESPONSE"|jq -r '.message')
ipwhois[vpn]=$(echo "$RESPONSE"|jq -r '.vpn')
ipwhois[proxy]=$(echo "$RESPONSE"|jq -r '.proxy')
ipwhois[tor]=$(echo "$RESPONSE"|jq -r '.tor')
ipwhois[hosting]=$(echo "$RESPONSE"|jq -r '.hosting')
fi
}
db_ipdata(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPData $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-8-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipdata=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://api.ipdata.co/$IP?api-key=test")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipdata[status]="null"
else
ipdata[status]=$(echo "$RESPONSE"|jq -r '.message')
ipdata[threatbot]=$(echo "$RESPONSE"|jq -r '.threat.bot')
fi
}
db_ipqs(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPQS $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-7-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipqs=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://www.ipqualityscore.com/api/json/ip/2i2n7Nds32dO7w5rC1u9X0a5J4x6P0a8/$IP")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
ipqs[status]="null"
else
ipqs[status]=$(echo "$RESPONSE"|jq -r '.message')
ipqs[vpn]=$(echo "$RESPONSE"|jq -r '.vpn')
ipqs[proxy]=$(echo "$RESPONSE"|jq -r '.proxy')
ipqs[tor]=$(echo "$RESPONSE"|jq -r '.tor')
ipqs[bot_status]=$(echo "$RESPONSE"|jq -r '.bot_status')
ipqs[abuse_velocity]=$(echo "$RESPONSE"|jq -r '.abuse_velocity')
fi
}
show_head(){
kill_progress_bar
local temp_info="$Font_Cyan$Font_B$(calc_padding "${shead[title]}" "${shead[ltitle]}")${shead[title]}$Font_Suffix"
if [[ $mode_lite -eq 1 ]];then
temp_info="$Font_Cyan$Font_B$(calc_padding "${shead[title_lite]}" "${shead[ltitle_lite]}")${shead[title_lite]}$Font_Suffix"
fi
echo -ne "\r$temp_info"
echo -ne "$Font_Cyan$Font_B$(calc_padding "${shead[ver]} $(if [[ $fullIP -eq 0 ]];then echo -ne "$IPhide";else echo -ne "$IP";fi) ${shead[time]}" 70)${shead[ver]} $(if [[ $fullIP -eq 0 ]];then echo -ne "$IPhide";else echo -ne "$IP";fi) ${shead[time]}$Font_Suffix"
echo -ne "$Font_Cyan$Font_B$(calc_padding "${shead[bash]}" 70)${shead[bash]}$Font_Suffix"
echo -ne "$Font_Cyan$Font_B$(calc_padding "${shead[git]}" 70)${shead[git]}$Font_Suffix"
echo -ne "\\r\\n"
echo -ne "$Font_Suffix"
}
show_basic(){
echo -ne "${sbasic[title]}\\n"
echo -ne "${sbasic[asn]}${maxmind[asn]} ${sbasic[org]}${maxmind[org]}\\n"
echo -ne "${sbasic[location]}${maxmind[dms]}\\n"
echo -ne "${sbasic[map]}${maxmind[map]}\\n"
echo -ne "${sbasic[city]}${maxmind[city]} ${sbasic[country]}${maxmind[citycountry]} (${maxmind[citycountrycode]})\\n"
echo -ne "${sbasic[regcountry]}${maxmind[regcountry]} (${maxmind[regcountrycode]})\\n"
echo -ne "${sbasic[continent]}${maxmind[continent]} (${maxmind[continentcode]})\\n"
echo -ne "${sbasic[timezone]}${maxmind[timezone]}\\n"
echo -ne "${sbasic[type]}"
if [[ ${maxmind[countrycode]} == ${maxmind[regcountrycode]} ]];then
echo -ne "${sbasic[type0]}\\n"
else
echo -ne "${sbasic[type1]}\\n"
fi
}
show_basic_lite(){
echo -ne "${sbasic[title_lite]}\\n"
echo -ne "${sbasic[asn]}${ipinfo[asn]} ${sbasic[org]}${ipinfo[org]}\\n"
echo -ne "${sbasic[location]}${ipinfo[dms]}\\n"
echo -ne "${sbasic[city]}${ipinfo[city]} ${sbasic[country]}${ipinfo[country]} (${ipinfo[countrycode]})\\n"
echo -ne "${sbasic[continent]}${ipinfo[continent]} (${ipinfo[continentcode]})\\n"
echo -ne "${sbasic[timezone]}${ipinfo[timezone]}\\n"
echo -ne "${sbasic[type]}"
if [[ ${ipinfo[countrycode]} == ${ipinfo[regcountrycode]} ]];then
echo -ne "${sbasic[type0]}\\n"
else
echo -ne "${sbasic[type1]}\\n"
fi
}
show_type(){
echo -ne "${stype[title]}\\n"
echo -ne "${stype[db]}${ip2location[category]} ${stype[usetype]}${ip2location[usagetype]} ${stype[comtype]}"
local type_val=""
case "${ipregistry[companytype]}" in
"business")type_val="${stype[business]}"
;;
"education")type_val="${stype[education]}"
;;
"isp")type_val="${stype[isp]}"
;;
"hosting")type_val="${stype[hosting]}"
;;
"government")type_val="${stype[government]}"
;;
"banking")type_val="${stype[banking]}"
;;
"organization")type_val="${stype[organization]}"
;;
"military")type_val="${stype[military]}"
;;
"library")type_val="${stype[library]}"
;;
"cdn")type_val="${stype[cdn]}"
;;
"line-isp")type_val="${stype[lineisp]}"
;;
"mobile-isp")type_val="${stype[mobile]}"
;;
"web-spider")type_val="${stype[spider]}"
;;
"reserved")type_val="${stype[reserved]}"
;;
*)type_val="${stype[other]}"
;;
esac
echo -ne "$type_val\\n"
}
show_type_lite(){
echo -ne "${stype[title]}\\n"
echo -ne "${stype[db]}N/A ${stype[usetype]}${dbip[usagetype]} ${stype[comtype]}"
local type_val=""
case "${dbip[usagetype]}" in
"Business")type_val="${stype[business]}"
;;
"Education")type_val="${stype[education]}"
;;
"ISP")type_val="${stype[isp]}"
;;
"Hosting")type_val="${stype[hosting]}"
;;
"Government")type_val="${stype[government]}"
;;
"Banking")type_val="${stype[banking]}"
;;
"Organization")type_val="${stype[organization]}"
;;
"Military")type_val="${stype[military]}"
;;
"Library")type_val="${stype[library]}"
;;
"CDN")type_val="${stype[cdn]}"
;;
"Line-ISP")type_val="${stype[lineisp]}"
;;
"Mobile-ISP")type_val="${stype[mobile]}"
;;
"Web-Spider")type_val="${stype[spider]}"
;;
"Reserved")type_val="${stype[reserved]}"
;;
*)type_val="${stype[other]}"
;;
esac
echo -ne "$type_val\\n"
}
show_score(){
echo -ne "${sscore[title]}\\n"
echo -ne "${sscore[range]}\\n"
echo -ne "${sfactor[factor]}${abuseipdb[score]}${sscore[colon]}${sfactor[proxy]}${ipapi[proxy]}${sscore[colon]}${sfactor[hosting]}${ipapi[hosting]}${sscore[colon]}${sfactor[vpn]}${ipwhois[vpn]}${sscore[colon]}${sfactor[tor]}${ipwhois[tor]}${sscore[colon]}${sfactor[robot]}${ipdata[threatbot]}\\n"
}
show_factor(){
echo -ne "${sfactor[title]}\\n"
echo -ne "${sfactor[proxy]}"
if [[ "${ipwhois[proxy]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[tor]}"
if [[ "${ipwhois[tor]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[vpn]}"
if [[ "${ipwhois[vpn]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[server]}"
if [[ "${ipapi[hosting]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[abuser]}"
if [[ "${abuseipdb[score]}" -gt 0 ]];then echo -ne "${sfactor[yes]}";else echo -ne "${sfactor[no]}";fi
echo -ne "${sfactor[robot]}"
if [[ "${ipdata[threatbot]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "\\n"
}
show_factor_lite(){
echo -ne "${sfactor[title]}\\n"
echo -ne "${sfactor[proxy]}"
if [[ "${ipwhois[proxy]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[tor]}"
if [[ "${ipwhois[tor]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[vpn]}"
if [[ "${ipwhois[vpn]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[server]}"
if [[ "${ipapi[hosting]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "${sfactor[abuser]}${sfactor[na]}"
echo -ne "${sfactor[robot]}"
if [[ "${ipdata[threatbot]}" == "false" ]];then echo -ne "${sfactor[no]}";else echo -ne "${sfactor[yes]}";fi
echo -ne "\\n"
}
show_media(){
local check_media_services=(cloudflare tiktok disney netflix youtube amazon spotify chatgpt)
echo -ne "${smedia[title]}\\n"
for service in "${check_media_services[@]}";do
local region="${!service[region]}"
local type="${!service[type]}"
local status="${!service[status]}"
[[ -z $region ]]&&region="${smedia[nodata]}"
[[ -z $type ]]&&type="${smedia[nodata]}"
[[ -z $status ]]&&status="${smedia[nodata]}"
echo -ne "${smedia[meida]}${service^} ${smedia[status]}$status ${smedia[region]}$region ${smedia[type]}$type\\n"
done
}
show_tail(){
countRunTimes
echo -ne "${stail[stoday]}${stail[today]}${stail[stotal]}${stail[total]}${stail[thanks]}\\n"
}
save_json(){
local json_string
json_string=$(jq -n \
--arg ip "$IP" \
--arg iplong "$IPhide" \
--arg asn "${maxmind[asn]:-"N/A"}" \
--arg org "${maxmind[org]:-"N/A"}" \
--arg country "${maxmind[country]:-"N/A"}" \
--arg countrycode "${maxmind[countrycode]:-"N/A"}" \
--arg regcountry "${maxmind[regcountry]:-"N/A"}" \
--arg regcountrycode "${maxmind[regcountrycode]:-"N/A"}" \
--arg city "${maxmind[city]:-"N/A"}" \
--arg timezone "${maxmind[timezone]:-"N/A"}" \
--arg lat "${maxmind[lat]:-"N/A"}" \
--arg lon "${maxmind[lon]:-"N/A"}" \
--arg map "${maxmind[map]:-"N/A"}" \
--arg usagetype "${ip2location[usagetype]:-"N/A"}" \
--arg companytype "${ipregistry[companytype]:-"N/A"}" \
--arg proxy "${ipwhois[proxy]:-"N/A"}" \
--arg vpn "${ipwhois[vpn]:-"N/A"}" \
--arg tor "${ipwhois[tor]:-"N/A"}" \
--arg hosting "${ipapi[hosting]:-"N/A"}" \
--arg abuseipdbscore "${abuseipdb[score]:-0}" \
--arg threatbot "${ipdata[threatbot]:-"N/A"}" \
'{
"ip": $ip,
"masked_ip": $iplong,
"asn": $asn,
"organization": $org,
"country": $country,
"country_code": $countrycode,
"registered_country": $regcountry,
"registered_country_code": $regcountrycode,
"city": $city,
"timezone": $timezone,
"latitude": $lat,
"longitude": $lon,
"google_map": $map,
"usage_type": $usagetype,
"company_type": $companytype,
"is_proxy": ($proxy == "true"),
"is_vpn": ($vpn == "true"),
"is_tor": ($tor == "true"),
"is_hosting": ($hosting == "true"),
"abuse_score": ($abuseipdbscore | tonumber),
"is_bot": ($threatbot == "true")
}' )
ipjson=$(echo "$json_string"|jq -c '.')
}
while getopts ":46fhji:l:no:x:yEM" optname;do
case "$optname" in
"4")IPV4check=1
IPV6check=0
;;
"6")IPV4check=0
IPV6check=1
;;
"f")fullIP=1
;;
"h")echo "$shelp"
exit 0
;;
"j")mode_json=1
;;
"i")useNIC="-interface $OPTARG"
if [[ "$OPTARG" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]];then
useNIC="-local-arg $OPTARG"
IPV4check=1
IPV6check=0
elif [[ "$OPTARG" =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ ]];then
useNIC="-local-arg $OPTARG"
IPV4check=0
IPV6check=1
fi
;;
"l")YY="$OPTARG"
;;
"n")mode_no=1
;;
"o")mode_output=1
outputfile="$OPTARG"
if [[ -f "$outputfile" ]]&&[[ $mode_json -eq 0 ]];then
ERRORcode=10
elif [[ ! -w "$(dirname "$outputfile")" ]];then
ERRORcode=11
fi
;;
"x")usePROXY="-x $OPTARG"
CurlARG="$usePROXY"
;;
"y")mode_yes=1
;;
"E")YY="en"
;;
"M")mode_menu=1
;;
":")echo "${swarn[1]}"
ERRORcode=1
;;
*)echo "${swarn[1]}"
ERRORcode=1
;;
esac
done
if [[ $ERRORcode -ne 0 ]];then
echo "${swarn[$ERRORcode]}"
exit 1
fi
set_language
if [[ $mode_no -eq 0 ]];then
install_dependencies
if [[ $ERRORcode -ne 0 ]];then
echo "${swarn[$ERRORcode]}"
exit 1
fi
fi
generate_random_user_agent
CurlARG="$CurlARG -A \"$UA_Browser\""
check_connectivity
adapt_locale
if [[ $IPV4check -eq 1 ]];then
get_ipv4
if [[ $IPV4work -eq 0 ]];then
echo "${swarn[40]}"
exit 1
fi
fi
if [[ $IPV6check -eq 1 ]];then
get_ipv6
if [[ $IPV6work -eq 0 ]];then
echo "${swarn[60]}"
exit 1
fi
fi
if [[ $IPV4check -eq 1 ]];then
IP="$IPV4"
else
IP="$IPV6"
fi
hide_ipv4 "$IPV4"
hide_ipv6 "$IPV6"
db_maxmind $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
if [[ $mode_lite -eq 1 ]];then
db_ipinfo $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_dbip $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
else
db_ipregistry $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_ip2location $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
fi
db_ipapi $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_ipwhois $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_ipdata $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_abuseipdb $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
db_ipqs $(if [[ $IPV4check -eq 1 ]];then echo -ne "4";else echo -ne "6";fi)
if [[ $mode_lite -eq 0 ]];then
local ip_report=$(show_head
show_basic
show_type
show_score
show_factor
show_media
show_tail)
else
local ip_report=$(show_head
show_basic_lite
show_type_lite
show_score
show_factor_lite
show_media
show_tail)
fi
local report_link=""
save_json
[[ $mode_lite -eq 0 ]]&&report_link=$(curl -$2 -s -X POST http://upload.check.place -d "type=ip" --data-urlencode "json=$ipjson" --data-urlencode "content=$ip_report")
[[ mode_json -eq 0 ]]&&echo -ne "\r$ip_report\\n"
[[ mode_json -eq 0 && $report_link == *"https://Report.Check.Place/"* ]]&&echo -ne "\r${stail[link]}$report_link$Font_Suffix\\n"
[[ mode_json -eq 1 ]]&&echo -ne "\r$ipjson\\n"
echo -ne "\r\\n"
if [[ mode_output -eq 1 ]];then
case "$outputfile" in
*.[aA][nN][sS][iI])echo "$ip_report" >>"$outputfile" 2>/dev/null
;;
*.[jJ][sS][oO][nN])echo "$ipjson" >>"$outputfile" 2>/dev/null
;;
*.[aA][nN][yY][oO][tT][hH][eE][rR])echo "$ip_report" >>"$outputfile" 2>/dev/null
;;
esac
fi