#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

# Root
[[ $(id -u) != 0 ]] && echo -e " please use ${red}root ${none} user to run ${yellow}~(^_^) ${none}" && exit 1

_version="v3.57"

cmd="apt-get"

sys_bit=$(uname -m)

case $sys_bit in
i[36]86)
	v2ray_bit="32"
	caddy_arch="386"
	;;
'amd64' | x86_64)
	v2ray_bit="64"
	caddy_arch="amd64"
	;;
*armv6*)
	v2ray_bit="arm32-v6"
	caddy_arch="arm6"
	;;
*armv7*)
	v2ray_bit="arm32-v7a"
	caddy_arch="arm7"
	;;
*aarch64* | *armv8*)
	v2ray_bit="arm64-v8a"
	caddy_arch="arm64"
	;;
*)
	echo -e " 
	${red} ${none} not support your os ${yellow}(-_-) ${none}

	ps: only support Ubuntu 16+ / Debian 8+ / CentOS 7+ 
	" && exit 1
	;;
esac

if [[ $(command -v yum) ]]; then

	cmd="yum"

fi

backup="/etc/v2ray/233blog_v2ray_backup.conf"

if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/233boy/v2ray ]]; then

	. $backup

elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/233blog_v2ray_backup.txt && -d /etc/v2ray/233boy/v2ray ]]; then

	. /etc/v2ray/233boy/v2ray/tools/v1xx_to_v3xx.sh

else
	echo -e " ${red} error occors please reinstall ${none} ${yellow}~(^_^) ${none}" && exit 1
fi

if [[ $mark != "v3" ]]; then
	. /etc/v2ray/233boy/v2ray/tools/v3.sh
fi
if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
	dynamicPort=true
	port_range="${v2ray_dynamicPort_start}-${v2ray_dynamicPort_end}"
fi
if [[ $path_status ]]; then
	is_path=true
fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="e55c8d17-2cf3-b21a-bcf1-eeacb011ed79"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/233blog_v2ray_config.json"
v2ray_pid=$(pgrep -f /usr/bin/v2ray/v2ray)
caddy_pid=$(pgrep -f /usr/local/bin/caddy)
_v2ray_sh="/usr/local/sbin/v2ray"
v2ray_ver="$(/usr/bin/v2ray/v2ray -version | head -n 1 | cut -d " " -f2)"
. /etc/v2ray/233boy/v2ray/src/init.sh
systemd=true
# _test=true

# fix VMessAEAD
if [[ ! $(grep 'v2ray.vmess.aead.forced=false' /lib/systemd/system/v2ray.service) ]]; then
	sed -i 's|ExecStart=|ExecStart=/usr/bin/env v2ray.vmess.aead.forced=false |' /lib/systemd/system/v2ray.service
	systemctl daemon-reload
	systemctl restart v2ray
fi

# fix caddy2 config
if [[ $caddy ]]; then
	/usr/local/bin/caddy version >/dev/null 2>&1
	if [[ $? == 1 ]]; then
		echo -e "\n $yellow warn: auto update Caddy  $none  \n"
		systemctl stop caddy
		_load download-caddy.sh
		_download_caddy_file
		_install_caddy_service
		systemctl daemon-reload
		_load caddy-config.sh
		systemctl restart caddy
		echo -e "\n $green update Caddy finish, 。 $none  \n"
		exit 0
	fi
fi

if [[ $v2ray_ver != v* ]]; then
	v2ray_ver="v$v2ray_ver"
fi
if [[ ! -f $_v2ray_sh ]]; then
	mv -f /usr/local/bin/v2ray $_v2ray_sh
	chmod +x $_v2ray_sh
	echo -e "\n $yellow 警告: 请重新登录 SSH 以避免出现 v2ray 命令未找到的情况。$none  \n" && exit 1
fi

if [ $v2ray_pid ]; then
	v2ray_status="$green running $none"
else
	v2ray_status="$red not running $none"
fi
if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy_pid && $caddy ]]; then
	caddy_run_status="$green running $none"
else
	caddy_run_status="$red not running $none"
fi

_load transport.sh
ciphers=(
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

get_transport_args() {
	_load v2ray-info.sh
	_v2_args
}
create_vmess_URL_config() {

	[[ -z $net ]] && get_transport_args

	if [[ $v2ray_transport == [45] ]]; then
		cat >/etc/v2ray/vmess_qr.json <<-EOF
			{
				"v": "2",
				"ps": "233v2.com_${domain}",
				"add": "${domain}",
				"port": "443",
				"id": "${v2ray_id}",
				"aid": "${alterId}",
				"net": "${net}",
				"type": "none",
				"host": "${domain}",
				"path": "$_path",
				"tls": "tls"
			}
		EOF
	elif [[ $v2ray_transport == 33 ]]; then
		cat >/etc/v2ray/vmess_qr.json <<-EOF
			vless://${v2ray_id}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${_path}#233v2_${domain}
		EOF
	else
		[[ -z $ip ]] && get_ip
		cat >/etc/v2ray/vmess_qr.json <<-EOF
			{
				"v": "2",
				"ps": "233v2.com_${ip}",
				"add": "${ip}",
				"port": "${v2ray_port}",
				"id": "${v2ray_id}",
				"aid": "${alterId}",
				"net": "${net}",
				"type": "${header}",
				"host": "${host}",
				"path": "",
				"tls": ""
			}
		EOF
	fi
}
view_v2ray_config_info() {

	_load v2ray-info.sh
	_v2_args
	_v2_info
}
get_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none view Shadowsocks config"
			echo
			echo -e "$yellow 2. $none gen QR"
			echo
			read -p "$(echo -e "chose [${magenta}1-2$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					view_shadowsocks_config_info
					break
					;;
				2)
					get_shadowsocks_config_qr_link
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else
		shadowsocks_config
	fi
}
view_shadowsocks_config_info() {
	if [[ $shadowsocks ]]; then
		_load ss-info.sh
	else
		shadowsocks_config
	fi
}
get_shadowsocks_config_qr_link() {
	if [[ $shadowsocks ]]; then
		get_ip
		_load qr.sh
		_ss_qr
	else
		shadowsocks_config
	fi

}

get_shadowsocks_config_qr_ask() {
	echo
	while :; do
		echo -e "do you need to gen $yellow Shadowsocks config $none QR [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${magenta}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			get_shadowsocks_config_qr_link
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none update Shadowsocks  port"
			echo
			echo -e "$yellow 2. $none update  Shadowsocks 密码"
			echo
			echo -e "$yellow 3. $none update  Shadowsocks 加密协议"
			echo
			echo -e "$yellow 4. $none shutdown Shadowsocks"
			echo
			read -p "$(echo -e "choose [${magenta}1-4$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					change_shadowsocks_port
					break
					;;
				2)
					change_shadowsocks_password
					break
					;;
				3)
					change_shadowsocks_ciphers
					break
					;;
				4)
					disable_shadowsocks
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else

		shadowsocks_config
	fi
}
shadowsocks_config() {
	echo
	echo
	echo -e " $red not enable Shadowsocks $none... you can enable it right now ^_^"
	echo
	echo

	while :; do
		echo -e "are you sure to config ${yellow}Shadowsocks${none} [${magenta}Y/N$none]"
		read -p "$(echo -e "(default [${cyan}N$none]):") " install_shadowsocks
		[[ -z "$install_shadowsocks" ]] && install_shadowsocks="n"
		if [[ "$install_shadowsocks" == [Yy] ]]; then
			echo
			shadowsocks=true
			shadowsocks_port_config
			shadowsocks_password_config
			shadowsocks_ciphers_config
			pause
			backup_config +ss
			ssport=$new_ssport
			sspass=$new_sspass
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
		elif [[ "$install_shadowsocks" == [Nn] ]]; then
			echo
			echo -e " $green cancel config Shadowsocks ....$none"
			echo
			break
		else
			error
		fi

	done
}
shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e "input "$yellow"Shadowsocks"$none"  port ["$magenta"1-65535"$none"]，can not same with "$yellow"V2ray"$none"  port"
		read -p "$(echo -e "(default port: ${cyan}${random}$none):") " new_ssport
		[ -z "$new_ssport" ] && new_ssport=$random
		case $new_ssport in
		$v2ray_port)
			echo
			echo -e " can not same with $cyan V2Ray  port $none一毛一样...."
			echo
			echo -e " current V2Ray  port：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e "already use "$green"WebSocket + TLS $none或$green HTTP/2"$none"  transfer protocol."
				echo
				echo -e "so can not use "$magenta"80"$none" 或 "$magenta"443"$none"  port"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				echo
				echo -e "this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
				error
			elif [[ $socks && $new_ssport == $socks_port ]]; then
				echo
				echo -e "this port is conflict with  Socks  port...current Socks  port: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $new_ssport == $mtproto_port ]]; then
				echo
				echo -e "this port is conflict with MTProto  port冲突...current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks  port = $cyan$new_ssport$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}

shadowsocks_password_config() {

	while :; do
		echo -e "input "$yellow"Shadowsocks"$none" password"
		read -p "$(echo -e "(default: ${cyan}233blog.com$none)"): " new_sspass
		[ -z "$new_sspass" ] && new_sspass="233blog.com"
		case $new_sspass in
		*[/$]*)
			echo
			echo -e " password can not includde $red / $none or $red $ $none.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks password = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done

}

shadowsocks_ciphers_config() {

	while :; do
		echo -e "choose "$yellow"Shadowsocks"$none" encrypt protocol [${magenta}1-3$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(defaule: ${cyan}${ciphers[1]}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && ssciphers_opt=2
		case $ssciphers_opt in
		[1-3])
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Shadowsocks  encrypt protocol = $cyan${new_ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
}

change_shadowsocks_port() {
	echo
	while :; do
		echo -e "input "$yellow"Shadowsocks"$none"  port ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(current port: ${cyan}$ssport$none):") " new_ssport
		[ -z "$new_ssport" ] && error && continue
		case $new_ssport in
		$ssport)
			echo
			echo " same with current port一毛一样.... update 个鸡鸡哦"
			error
			;;
		$v2ray_port)
			echo
			echo -e " can not same with $cyan V2Ray  port $none一毛一样...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e "already use "$green"WebSocket + TLS $none或$green HTTP/2"$none"  transfer protocol."
				echo
				echo -e "so you can not use "$magenta"80"$none" 或 "$magenta"443"$none"  port"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				echo
				echo -e " this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
				error
			elif [[ $socks && $new_ssport == $socks_port ]]; then
				echo
				echo -e "his port is conflict with  Socks  port冲突...current Socks  port: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $new_ssport == $mtproto_port ]]; then
				echo
				echo -e "his port is conflict with  MTProto  port冲突...current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks  port = $cyan$new_ssport$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config ssport
				ssport=$new_ssport
				config
				clear
				view_shadowsocks_config_info
				# get_shadowsocks_config_qr_ask
				break
			fi
			;;
		*)
			error
			;;
		esac

	done
}
change_shadowsocks_password() {
	echo
	while :; do
		echo -e "input "$yellow"Shadowsocks"$none" password"
		read -p "$(echo -e "(current pwd：${cyan}$sspass$none)"): " new_sspass
		[ -z "$new_sspass" ] && error && continue
		case $new_sspass in
		$sspass)
			echo
			echo " 跟current密码一毛一样.... update 个鸡鸡哦"
			error
			;;
		*[/$]*)
			echo
			echo -e " 由于这个脚本太辣鸡了..所以密码不能包含$red / $none或$red $ $none这两个符号.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks password = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config sspass
			sspass=$new_sspass
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
			;;
		esac

	done

}

change_shadowsocks_ciphers() {
	echo
	while :; do
		echo -e "input "$yellow"Shadowsocks"$none"  encrypt protocol  [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(current  encrypt protocol : ${cyan}${ssciphers}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && error && continue
		case $ssciphers_opt in
		[1-3])
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			if [[ $new_ssciphers == $ssciphers ]]; then
				echo
				echo " 跟current加密协议一毛一样.... update 个鸡鸡哦"
				error && continue
			fi
			echo
			echo
			echo -e "$yellow Shadowsocks  encrypt protocol  = $cyan${new_ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config ssciphers
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
			;;
		*)
			error
			;;
		esac

	done

}
disable_shadowsocks() {
	echo

	while :; do
		echo -e "are you sure to disable ${yellow}Shadowsocks${none} [${magenta}Y/N$none]"
		read -p "$(echo -e "(default [${cyan}N$none]):") " y_n
		[[ -z "$y_n" ]] && y_n="n"
		if [[ "$y_n" == [Yy] ]]; then
			echo
			echo
			echo -e "$yellow disable Shadowsocks = $cyan yes $none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config -ss
			shadowsocks=''
			config
			# clear
			echo
			echo
			echo
			echo -e "$green Shadowsocks disable...but you still can enable Shadowsocks ...只要你喜欢$none"
			echo
			break
		elif [[ "$y_n" == [Nn] ]]; then
			echo
			echo -e " $green cancel to disable Shadowsocks ....$none"
			echo
			break
		else
			error
		fi

	done
}
change_v2ray_config() {
	local _menu=(
		"update V2Ray port"
		"update V2Ray transfer protocol"
		"update V2Ray dynamic port (if possible)"
		"update user ID ( UUID )"
		"update TLS domain (if possible)"
		"update bypass path (if possible)"
		"update feign web url (if possible)"
		"disable feign web 和 bypass (if possible)"
		"enable / disable ad block"
	)
	while :; do
		for ((i = 1; i <= ${#_menu[*]}; i++)); do
			if [[ "$i" -le 9 ]]; then
				echo
				echo -e "$yellow  $i. $none${_menu[$i - 1]}"
			else
				echo
				echo -e "$yellow $i. $none${_menu[$i - 1]}"
			fi
		done
		echo
		read -p "$(echo -e "choose [${magenta}1-${#_menu[*]}$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				change_v2ray_port
				break
				;;
			2)
				change_v2ray_transport
				break
				;;
			3)
				change_v2ray_dynamicport
				break
				;;
			4)
				change_v2ray_id
				break
				;;
			5)
				change_domain
				break
				;;
			6)
				change_path_config
				break
				;;
			7)
				change_proxy_site_config
				break
				;;
			8)
				disable_path
				break
				;;
			9)
				blocked_hosts
				break
				;;
			[aA][Ii][aA][Ii] | [Dd][Dd])
				custom_uuid
				break
				;;
			[Dd] | [Aa][Ii] | 233 | 233[Bb][Ll][Oo][Gg] | 233[Bb][Ll][Oo][Gg].[Cc][Oo][Mm] | 233[Bb][Oo][Yy] | [Aa][Ll][Tt][Ee][Rr][Ii][Dd])
				change_v2ray_alterId
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
change_v2ray_port() {
	if [[ $v2ray_transport == 4 ]]; then
		echo
		echo -e " now you are using $yellow WebSocket + TLS $none transfer protocol...it does't matter to change V2Ray port or not"
		echo
		echo " if you want use other port...you can update  V2Ray  transfer protocol..then update  V2Ray  port"
		echo
		change_v2ray_transport_ask
	elif [[ $v2ray_transport == 5 ]]; then
		echo
		echo -e " now you use $yellow HTTP/2 $none transfer protocol...it does't matter to update  V2Ray  port or not"
		echo
		echo " if you want use other port...you can update  V2Ray  transfer protocol..then update  V2Ray  port"
		echo
		change_v2ray_transport_ask
	else
		echo
		while :; do
			echo -e "input "$yellow"V2Ray"$none"  port ["$magenta"1-65535"$none"]"
			read -p "$(echo -e "(current port: ${cyan}${v2ray_port}$none):")" v2ray_port_opt
			[[ -z $v2ray_port_opt ]] && error && continue
			case $v2ray_port_opt in
			$v2ray_port)
				echo
				echo " 哎呀...跟current port一毛一样呀... update 个鸡鸡哦"
				error
				;;
			[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				if [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $v2ray_port_opt || $v2ray_dynamicPort_end == $v2ray_port_opt ]]; then
					echo
					echo -e " this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
					error
				elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $v2ray_port_opt && $v2ray_port_opt -le $v2ray_dynamicPort_end ]]; then
					echo
					echo -e " this port is conflict with  V2Ray dynamic port ，current V2Ray dynamic port range：${cyan}$port_range${none}"
					error
				elif [[ $shadowsocks && $v2ray_port_opt == $ssport ]]; then
					echo
					echo -e "this port is conflict with  Shadowsocks  port冲突...current Shadowsocks  port: ${cyan}$ssport$none"
					error
				elif [[ $socks && $v2ray_port_opt == $socks_port ]]; then
					echo
					echo -e "this port is conflict with  Socks  port冲突...current Socks  port: ${cyan}$socks_port$none"
					error
				elif [[ $mtproto && $v2ray_port_opt == $mtproto_port ]]; then
					echo
					echo -e "this port is conflict with  MTProto  port冲突...current MTProto  port: ${cyan}$mtproto_port$none"
					error
				else
					echo
					echo
					echo -e "$yellow V2Ray  port = $cyan$v2ray_port_opt$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config v2ray_port
					v2ray_port=$v2ray_port_opt
					config
					clear
					view_v2ray_config_info
					# download_v2ray_config_ask
					break
				fi
				;;
			*)
				error
				;;
			esac

		done
	fi

}
download_v2ray_config_ask() {
	echo
	while :; do
		echo -e "do you need to  download V2Ray config / gen config url / gen QR [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			download_v2ray_config
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_v2ray_transport_ask() {
	echo
	while :; do
		echo -e "are you sure to update $yellow V2Ray $none transfer protocol [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		[ -z $y_n ] && break
		if [[ $y_n == [Yy] ]]; then
			change_v2ray_transport
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done
}
change_v2ray_transport() {
	echo
	while :; do
		echo -e "choose "$yellow"V2Ray"$none" transfer protocol [${magenta}1-${#transport[*]}$none]"
		echo
		for ((i = 1; i <= ${#transport[*]}; i++)); do
			Stream="${transport[$i - 1]}"
			if [[ "$i" -le 9 ]]; then
				# echo
				echo -e "$yellow  $i. $none${Stream}"
			else
				# echo
				echo -e "$yellow $i. $none${Stream}"
			fi
		done
		echo
		echo "ps1: contain [dynamicPort] means that will enable dynamic port.."
		echo "ps2: [utp | srtp | wechat-video | dtls | wireguard] pretend to [BTdownload | video call | wechet video call | DTLS 1.2 data package | WireGuard data package]"
		echo
		read -p "$(echo -e "(cur transfer protocol : ${cyan}${transport[$v2ray_transport - 1]}$none)"):" v2ray_transport_opt
		if [ -z "$v2ray_transport_opt" ]; then
			error
		else
			case $v2ray_transport_opt in
			$v2ray_transport)
				echo
				echo " same with cur transfer protocol"
				error
				;;
			4 | 5 | 33)
				if [[ $v2ray_port == "80" || $v2ray_port == "443" ]]; then
					echo
					echo -e " if you want use ${cyan} ${transport[$v2ray_transport_opt - 1]} $none transfer protocol.. ${red}V2Ray port can not be 80 or 443 ...$none"
					echo
					echo -e " current V2Ray  port: ${cyan}$v2ray_port$none"
					error
				elif [[ $shadowsocks ]] && [[ $ssport == "80" || $ssport == "443" ]]; then
					echo
					echo -e " 抱歉...if you want use ${cyan} ${transport[$v2ray_transport_opt - 1]} $none transfer protocol.. ${red}Shadowsocks port can not be 80 or 443 ...$none"
					echo
					echo -e " current Shadowsocks  port: ${cyan}$ssport$none"
					error
				elif [[ $socks ]] && [[ $socks_port == "80" || $socks_port == "443" ]]; then
					echo
					echo -e " 抱歉...if you want use ${cyan} ${transport[$v2ray_transport_opt - 1]} $none transfer protocol.. ${red}Socks port can not be 80 or 443 ...$none"
					echo
					echo -e " current Socks  port: ${cyan}$socks_port$none"
					error
				elif [[ $mtproto ]] && [[ $mtproto_port == "80" || $mtproto_port == "443" ]]; then
					echo
					echo -e " 抱歉...if you want use ${cyan} ${transport[$v2ray_transport_opt - 1]} $none transfer protocol.. ${red}MTProto port can not be 80 or 443 ...$none"
					echo
					echo -e " current MTProto  port: ${cyan}$mtproto_port$none"
					error
				else
					echo
					echo
					echo -e "$yellow V2Ray  transfer protocol = $cyan${transport[$v2ray_transport_opt - 1]}$none"
					echo "----------------------------------------------------------------"
					echo
					break
				fi
				;;
			[1-9] | [1-2][0-9] | 3[0-3])
				echo
				echo
				echo -e "$yellow V2Ray  transfer protocol = $cyan${transport[$v2ray_transport_opt - 1]}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
			esac
		fi

	done
	pause

	if [[ $v2ray_transport_opt == [45] || $v2ray_transport_opt == 33 ]]; then
		tls_config
	elif [[ $v2ray_transport_opt -ge 18 && $v2ray_transport_opt -ne 33 ]]; then
		v2ray_dynamic_port_start
		v2ray_dynamic_port_end
		pause
		old_transport
		backup_config v2ray_transport v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	else
		old_transport
		backup_config v2ray_transport
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	fi

}
old_transport() {
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]]; then
		if [[ $caddy && $caddy_pid ]]; then
			do_service stop caddy
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		elif [[ $caddy ]]; then
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		fi
		if [[ $is_path ]]; then
			backup_config -path
		fi
	fi
}

tls_config() {
	while :; do
		echo
		echo
		echo
		echo -e "input a ${magenta}correct domain ${none} make sure it is correct !!!"
		read -p "(e.g : 233blog.com): " new_domain
		[ -z "$new_domain" ] && error && continue
		echo
		echo
		echo -e "$yellow your domain = $cyan$new_domain$none"
		echo "----------------------------------------------------------------"
		break
	done
	get_ip
	echo
	echo
	echo -e "$yellow please parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
	echo
	echo -e "$yellow  please parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
	echo
	echo -e "$yellow  please parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(is it parsed to: [${magenta}Y$none]):") " record
		if [[ -z "$record" ]]; then
			error
		else
			if [[ "$record" == [Yy] ]]; then
				domain_check
				echo
				echo
				echo -e "$yellow doamin parse = ${cyan} sure it is parsed $none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done

	if [[ $caddy ]]; then
		path_config_ask
		pause
		# domain_check
		backup_config v2ray_transport domain
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
		fi

		domain=$new_domain

		if [[ $systemd ]]; then
			systemctl enable caddy >/dev/null 2>&1
		else
			update-rc.d -f caddy defaults >/dev/null 2>&1
		fi
		v2ray_transport=$v2ray_transport_opt
		caddy_config
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	else
		if [[ $v2ray_transport_opt -ne 4 ]]; then
			path_config_ask
			pause
			domain_check
			backup_config v2ray_transport domain caddy
			if [[ $new_path ]]; then
				backup_config +path
				path=$new_path
				proxy_site=$new_proxy_site
				is_path=true
			fi
			domain=$new_domain
			install_caddy
			v2ray_transport=$v2ray_transport_opt
			caddy_config
			config
			caddy=true
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			auto_tls_config
		fi
	fi

}
auto_tls_config() {
	echo -e "

		install Caddy to achieve auto config TLS
		
		如果你已经安装 Nginx 或 Caddy

		$yellow并且..自己能搞定配置 TLS$none

		那么就不需要 打开自动配置 TLS
		"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(enable auto config TLS: [${magenta}Y/N$none]):") " auto_install_caddy
		if [[ -z "$auto_install_caddy" ]]; then
			error
		else
			if [[ "$auto_install_caddy" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow auto config TLS = $cyan enable $none"
				echo "----------------------------------------------------------------"
				echo
				path_config_ask
				pause
				domain_check
				backup_config v2ray_transport domain caddy
				if [[ $new_path ]]; then
					backup_config +path
					path=$new_path
					proxy_site=$new_proxy_site
					is_path=true
				fi
				domain=$new_domain
				install_caddy
				v2ray_transport=$v2ray_transport_opt
				caddy_config
				config
				caddy=true
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ "$auto_install_caddy" == [Nn] ]]; then
				echo
				echo
				echo -e "$yellow auto config TLS = $cyan disable $none"
				echo "----------------------------------------------------------------"
				echo
				pause
				domain_check
				backup_config v2ray_transport domain
				domain=$new_domain
				v2ray_transport=$v2ray_transport_opt
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			else
				error
			fi
		fi

	done
}

path_config_ask() {
	echo
	while :; do
		echo -e "enable web pretend and bypass [${magenta}Y/N$none]"
		read -p "$(echo -e "(default: [${cyan}N$none]):")" path_ask
		[[ -z $path_ask ]] && path_ask="n"

		case $path_ask in
		Y | y)
			path_config
			break
			;;
		N | n)
			echo
			echo
			echo -e "$yellow web pretend and bypass = $cyan no need $none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
path_config() {
	echo
	while :; do
		echo -e "input ${magenta} bypass path $none , e.g /233blog , just input 233blog "
		read -p "$(echo -e "(default: [${cyan}233blog$none]):")" new_path
		[[ -z $new_path ]] && new_path="233blog"

		case $new_path in
		*[/$]*)
			echo
			echo -e " 由于这个脚本太辣鸡了..所以分流的路径不能包含$red / $none或$red $ $none这两个符号.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow bypass path = ${cyan}/${new_path}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
	proxy_site_config
}
proxy_site_config() {
	echo
	while :; do
		echo -e "input ${magenta} correct  $none ${cyan} web url $none as ${cyan} pretend web $none , e.g https://liyafly.com"
		echo -e "举例...假设你current的域名是$green $domain $none, 伪装的网址的是 https://liyafly.com"
		echo -e "然后打开你的域名时候...显示出来的内容就是来自 https://liyafly.com 的内容"
		echo -e "其实就是一个反代...明白就好..."
		echo -e "如果不能伪装成功...可以使用 v2ray config  update 伪装的网址"
		read -p "$(echo -e "(默认: [${cyan}https://liyafly.com$none]):")" new_proxy_site
		[[ -z $new_proxy_site ]] && new_proxy_site="https://liyafly.com"

		case $new_proxy_site in
		*[#$]*)
			echo
			echo -e " 由于这个脚本太辣鸡了..所以伪装的网址不能包含$red # $none或$red $ $none这两个符号.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow pretend web = ${cyan}${new_proxy_site}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

install_caddy() {
	_load download-caddy.sh
	_download_caddy_file
	_install_caddy_service

}
caddy_config() {
	# local email=$(shuf -i1-10000000000 -n1)
	_load caddy-config.sh
	# systemctl restart caddy
	do_service restart caddy
}
v2ray_dynamic_port_start() {
	echo
	echo
	while :; do
		echo -e "input "$yellow"V2Ray dynamic port start "$none" range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(default port: ${cyan}10000$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && v2ray_dynamic_port_start_input=10000
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo "cannot same with V2Ray  port一毛一样...."
			echo
			echo -e " current V2Ray  port：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $shadowsocks && $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo -e "this port is conflict with Shadowsocks  port冲突...current Shadowsocks  port: ${cyan}$ssport$none"
				error
			elif [[ $socks && $v2ray_dynamic_port_start_input == $socks_port ]]; then
				echo
				echo -e "this port is conflict with Socks  port冲突...current Socks  port: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $v2ray_dynamic_port_start_input == $mtproto_port ]]; then
				echo
				echo -e "this port is conflict with MTProto  port冲突...current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray dynamic port start = $cyan$v2ray_dynamic_port_start_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi

			;;
		*)
			error
			;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi
	if [[ $socks ]] && [[ $v2ray_dynamic_port_start_input -lt $socks_port ]]; then
		lt_socks_port=true
	fi
	if [[ $mtproto ]] && [[ $v2ray_dynamic_port_start_input -lt $mtproto_port ]]; then
		lt_mtproto_port=true
	fi

}

v2ray_dynamic_port_end() {
	echo
	while :; do
		echo -e "input "$yellow"V2Ray dynamic port end "$none"range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(default port: ${cyan}20000$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && v2ray_dynamic_port_end_input=20000
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " 不能小于或等于 V2Ray 动态 port开始范围"
				echo
				echo -e " current V2Ray 动态 port开始：${cyan}$v2ray_dynamic_port_start_input${none}"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 V2Ray  port..."
				echo
				echo -e " current V2Ray  port: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 Shadowsocks  port..."
				echo
				echo -e " current Shadowsocks  port: ${cyan}$ssport$none"
				error
			elif [ $lt_socks_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $socks_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 Socks  port..."
				echo
				echo -e " current Socks  port: ${cyan}$socks_port$none"
				error
			elif [ $lt_mtproto_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $mtproto_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 MTProto  port..."
				echo
				echo -e " current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray dynamic port end = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
change_v2ray_dynamicport() {
	if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
		change_v2ray_dynamic_port_start
		change_v2ray_dynamic_port_end
		pause
		backup_config v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		config
		# clear
		echo
		echo -e "$green dynamic port update success...no need to update  V2Ray client config...保持原有的配置即可...$none"
		echo
	else
		echo
		echo -e "$red ...current transfer protocol not enable dynamic port...$none"
		echo
		while :; do
			echo -e "do you need  to update  transfer protocol [${magenta}Y/N$none]"
			read -p "$(echo -e "default [${cyan}N$none]:")" y_n
			if [[ -z $y_n ]]; then
				echo
				echo -e "$green cancel update  transfer protocol...$none"
				echo
				break
			else
				if [[ $y_n == [Yy] ]]; then
					change_v2ray_transport
					break
				elif [[ $y_n == [Nn] ]]; then
					echo
					echo -e "$green cancel update  transfer protocol...$none"
					echo
					break
				else
					error
				fi
			fi
		done

	fi
}
change_v2ray_dynamic_port_start() {
	echo
	echo
	while :; do
		echo -e "input "$yellow"V2Ray dynamic port start "$none" range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(current dynamic start port: ${cyan}$v2ray_dynamicPort_start$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && error && continue
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " cannot same with V2Ray  port一毛一样...."
			echo
			echo -e " current V2Ray  port：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $shadowsocks && $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo -e "this port is conflict with Shadowsocks  port冲突...current Shadowsocks  port: ${cyan}$ssport$none"
				error
			elif [[ $socks && $v2ray_dynamic_port_start_input == $socks_port ]]; then
				echo
				echo -e "this port is conflict with Socks  port冲突...current Socks  port: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $v2ray_dynamic_port_start_input == $mtproto_port ]]; then
				echo
				echo -e "this port is conflict with MTProto  port冲突...current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray dynamic port start = $cyan$v2ray_dynamic_port_start_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi

			;;
		*)
			error
			;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi
	if [[ $socks ]] && [[ $v2ray_dynamic_port_start_input -lt $socks_port ]]; then
		lt_socks_port=true
	fi
	if [[ $mtproto ]] && [[ $v2ray_dynamic_port_start_input -lt $mtproto_port ]]; then
		lt_mtproto_port=true
	fi
}

change_v2ray_dynamic_port_end() {
	echo
	while :; do
		echo -e "input "$yellow"V2Ray dynamic port end "$none" range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(current dynamic port end: ${cyan}$v2ray_dynamicPort_end$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && error && continue
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " 不能小于或等于 V2Ray 动态 port开始范围"
				echo
				echo -e " current V2Ray 动态 port开始：${cyan}$v2ray_dynamic_port_start_input${none}"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 V2Ray  port..."
				echo
				echo -e " current V2Ray  port: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 Shadowsocks  port..."
				echo
				echo -e " current Shadowsocks  port: ${cyan}$ssport$none"
				error
			elif [ $lt_socks_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $socks_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 Socks  port..."
				echo
				echo -e " current Socks  port: ${cyan}$socks_port$none"
				error
			elif [ $lt_mtproto_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $mtproto_port ]]; then
				echo
				echo " V2Ray 动态 port结束范围 不能包括 MTProto  port..."
				echo
				echo -e " current MTProto  port: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray dynamic port end = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
change_v2ray_id() {
	echo
	while :; do
		echo -e "are you sure to update userID [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		if [[ -z $y_n ]]; then
			echo
			echo -e "$green cancel update userID...$none"
			echo
			break
		else
			if [[ $y_n == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow  update userID = $cyan yes $none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config uuid
				v2ray_id=$uuid
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ $y_n == [Nn] ]]; then
				echo
				echo -e "$green cancel update userID...$none"
				echo
				break
			else
				error
			fi
		fi
	done
}
change_domain() {
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		while :; do
			echo
			echo -e "input ${magenta} correct domain ${none}，make sure it is correct"
			read -p "$(echo -e "(current domain: ${cyan}$domain$none):") " new_domain
			[ -z "$new_domain" ] && error && continue
			if [[ $new_domain == $domain ]]; then
				echo
				echo -e " 跟current域名一毛一样啊... update 个鸡鸡哦"
				echo
				error && continue
			fi
			echo
			echo
			echo -e "$yellow your domain = $cyan$new_domain$none"
			echo "----------------------------------------------------------------"
			break
		done
		get_ip
		echo
		echo
		echo -e "$yellow parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
		echo
		echo -e "$yellow parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
		echo
		echo -e "$yellow parse $magenta$new_domain$none $yellow to: $cyan$ip$none"
		echo "----------------------------------------------------------------"
		echo

		while :; do

			read -p "$(echo -e "(parse is correct ?: [${magenta}Y$none]):") " record
			if [[ -z "$record" ]]; then
				error
			else
				if [[ "$record" == [Yy] ]]; then
					domain_check
					echo
					echo
					echo -e "$yellow domain parse = ${cyan} sure it is parsed$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					# domain_check
					backup_config domain
					domain=$new_domain
					caddy_config
					config
					clear
					view_v2ray_config_info
					# download_v2ray_config_ask
					break
				else
					error
				fi
			fi

		done
	else
		echo
		echo -e "$red 抱歉...不支持 update ...$none"
		echo
		echo -e " ps.. update  TLS domain only support transfer protocol that is ${yellow}WebSocket + TLS$none or ${yellow}HTTP/2$none and $yellow auto config TLS = enable $none"
		echo
		echo -e " current transfer protocol为: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " autoconfig TLS = ${cyan} enable $none"
		else
			echo -e " autoconfig TLS = $red disable $none"
		fi
		echo
	fi
}
change_path_config() {
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy && $is_path ]]; then
		echo
		while :; do
			echo -e "input ${magenta} bypass path $none , e.g /233blog , just input 233blog 即可"
			read -p "$(echo -e "(current bypass path: [${cyan}/${path}$none]):")" new_path
			[[ -z $new_path ]] && error && continue

			case $new_path in
			$path)
				echo
				echo -e " 大佬...跟 current分流的路径 一毛一样啊... update 个鸡鸡哦 "
				echo
				error
				;;
			*[/$]*)
				echo
				echo -e " 由于这个脚本太辣鸡了..所以分流的路径不能包含$red / $none或$red $ $none这两个符号.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow bypass path = ${cyan}/${new_path}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config path
		path=$new_path
		caddy_config
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	elif [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			echo
			echo
			echo " 给大佬点赞....好果断的放弃配置 网站伪装 和 路径分流"
			echo
			echo
		fi
	else
		echo
		echo -e "$red 抱歉...不支持 update ...$none"
		echo
		echo -e " 备注.. update  bypass path only support transfer protocol is that ${yellow}WebSocket + TLS$none or ${yellow}HTTP/2$none and $yellow autoconfgi TLS = enable $none"
		echo
		echo -e " current transfer protocol为: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " autoconfig TLS = ${cyan} enable $none"
		else
			echo -e " autoconfig TLS = $red disable $none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
change_proxy_site_config() {
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy && $is_path ]]; then
		echo
		while :; do
			echo -e "input ${magenta} correct $none ${cyan} web url $none as ${cyan} pretend web $none , e.g https://liyafly.com"
			echo -e "举例...你current的域名是$green $domain $none, 伪装的网址的是 https://liyafly.com"
			echo -e "然后打开你的域名时候...显示出来的内容就是来自 https://liyafly.com 的内容"
			echo -e "其实就是一个反代...明白就好..."
			echo -e "如果不能伪装成功...可以使用 v2ray config  update 伪装的网址"
			read -p "$(echo -e "(current pretend web: [${cyan}${proxy_site}$none]):")" new_proxy_site
			[[ -z $new_proxy_site ]] && error && continue

			case $new_proxy_site in
			*[#$]*)
				echo
				echo -e " 由于这个脚本太辣鸡了..所以伪装的网址不能包含$red # $none或$red $ $none这两个符号.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow pretend web = ${cyan}${new_proxy_site}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config proxy_site
		proxy_site=$new_proxy_site
		caddy_config
		echo
		echo
		echo " 哎哟...好像是 update success..."
		echo
		echo -e " open your domain  ${cyan}https://${domain}$none to check it"
		echo
		echo
	elif [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			echo
			echo
			echo " 给大佬点赞....好果断的放弃配置 网站伪装 和 路径分流"
			echo
			echo
		fi
	else
		echo
		echo -e "$red 抱歉...不支持 update ...$none"
		echo
		echo -e " 备注.. update pretend web only support transfer protocol is ${yellow}WebSocket + TLS$none or ${yellow}HTTP/2$none and $yellow auto config TLS = enable $none"
		echo
		echo -e " current transfer protocol为: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " 自动配置 TLS = ${cyan}打开$none"
		else
			echo -e " 自动配置 TLS = $red关闭$none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
domain_check() {
	# test_domain=$(dig $new_domain +short)
	test_domain=$(ping $new_domain -c 1 -4 -W 2 | grep -oE -m1 "([0-9]{1,3}\.){3}[0-9]{1,3}")
	# test_domain=$(wget -qO- --header='accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$new_domain&type=A" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
	# test_domain=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$new_domain&type=A" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
	if [[ $test_domain != $ip ]]; then
		echo
		echo -e "$red 检测域名解析错误check dns parse error....$none"
		echo
		echo -e " your domain: $yellow$new_domain$none not parse to : $cyan$ip$none"
		echo
		echo -e " your domain current parse to: $cyan$test_domain$none"
		echo
		echo "ps...如果你的域名是使用 Cloudflare 解析的话..在 Status 那里点一下那图标..让它变灰"
		echo
		exit 1
	fi
}
disable_path() {
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy && $is_path ]]; then
		echo

		while :; do
			echo -e "are you sure to disable ${yellow} pretend web and bypass path 和 路径分流${none} [${magenta}Y/N$none]"
			read -p "$(echo -e "(default [${cyan}N$none]):") " y_n
			[[ -z "$y_n" ]] && y_n="n"
			if [[ "$y_n" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow pretend web and bypass path 关闭 网站伪装 和 路径分流 = $cyan yes $none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config -path
				is_path=''
				caddy_config
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ "$y_n" == [Nn] ]]; then
				echo
				echo -e " $green cancel disable pretend web and bypass path ....$none"
				echo
				break
			else
				error
			fi

		done
	else
		echo
		echo -e "$red 抱歉...not support update ...$none"
		echo
		echo -e " current transfer protocol is: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " auto config TLS = ${cyan} enable $none"
		else
			echo -e " auto config TLS = $red disable $none"
		fi
		echo
		if [[ $is_path ]]; then
			echo -e " bypass = ${cyan} enable $none"
		else
			echo -e " bypass = $red disable $none"
		fi
		echo
		echo -e " must be  WebSocket + TLS or HTTP/2  transfer protocol, auto config TLS = ${cyan} enable 打开$none, bypass path = ${cyan} enable 打开$none, that can update "
		echo

	fi
}
blocked_hosts() {
	if [[ $ban_ad ]]; then
		local _info="$green已开启$none"
	else
		local _info="$red已关闭$none"
	fi
	_opt=''
	while :; do
		echo
		echo -e "$yellow 1. $none开启 广告拦截"
		echo
		echo -e "$yellow 2. $none关闭 广告拦截"
		echo
		echo "备注: 广告拦截是基于 域名 拦截的..所以也许会造成浏览网页的时候出现部分元素留白..或者其他问题"
		echo
		echo "反馈问题或请求拦截更多域名: https://github.com/233boy/v2ray/issues"
		echo
		echo -e "current广告拦截状态: $_info"
		echo
		read -p "$(echo -e "请选择 [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				if [[ $ban_ad ]]; then
					echo
					echo -e " 大胸弟...难不成你没有看到 (current广告拦截状态: $_info) 这个帅帅的提示么.....还开启个鸡鸡哦"
					echo
				else
					echo
					echo
					echo -e "$yellow 广告拦截 = $cyan开启$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config +ad
					ban_ad=true
					config
					echo
					echo
					echo -e "$green 广告拦截已开启...如果出现异常..那就关闭它咯$none"
					echo
				fi
				break
				;;
			2)
				if [[ $ban_ad ]]; then
					echo
					echo
					echo -e "$yellow 广告拦截 = $cyan关闭$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config -ad
					ban_ad=''
					config
					echo
					echo
					echo -e "$red 广告拦截已关闭...不过你也可以随时重新开启 ...只要你喜欢$none"
					echo
				else
					echo
					echo -e " 大胸弟...难不成你没有看到 (current广告拦截状态: $_info) 这个帅帅的提示么.....还关闭个鸡鸡哦"
					echo
				fi
				break
				;;
			*)
				error
				;;
			esac
		fi
	done

}
change_v2ray_alterId() {
	echo
	while :; do
		echo -e "input ${yellow}alterId${none} value [${magenta}0-65535$none]"
		read -p "$(echo -e "(current alterId: ${cyan}$alterId$none):") " new_alterId
		[[ -z $new_alterId ]] && error && continue
		case $new_alterId in
		$alterId)
			echo
			echo -e " 大佬...跟 current alterId 一毛一样啊... update 个鸡鸡哦 "
			echo
			error
			;;
		[0-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow alterId = $cyan$new_alterId$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config alterId
			alterId=$new_alterId
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
			break
			;;
		*)
			error
			;;
		esac
	done
}

custom_uuid() {
	echo
	while :; do
		echo -e "请输入$yello自定义的 UUID$none...(${cyan}UUID 格式一定要对!!!$none)"
		read -p "$(echo -e "(current UUID: ${cyan}${v2ray_id}$none)"): " myuuid
		[ -z "$myuuid" ] && error && continue
		case $myuuid in
		$v2ray_id)
			echo
			echo -e " 大佬...跟 current UUID 一毛一样啊... update 个鸡鸡哦 "
			echo
			error
			;;
		*[/$]* | *\&*)
			echo
			echo -e " 由于这个脚本太辣鸡了..所以 UUID 不能包含$red / $none或$red $ $none或$red & $none这三个符号.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow UUID = $cyan$myuuid$none"
			echo
			echo -e " if UUID not correct.. V2Ray will stopped...use $cyan v2ray reuuid$none 复活"
			echo "----------------------------------------------------------------"
			echo
			pause
			uuid=$myuuid
			backup_config uuid
			v2ray_id=$uuid
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
			break
			;;
		esac
	done
}
v2ray_service() {
	while :; do
		echo
		echo -e "$yellow 1. $none start V2Ray"
		echo
		echo -e "$yellow 2. $none stop V2Ray"
		echo
		echo -e "$yellow 3. $none restart V2Ray"
		echo
		echo -e "$yellow 4. $none view access log"
		echo
		echo -e "$yellow 5. $none view error log"
		echo
		read -p "$(echo -e "choose [${magenta}1-5$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				start_v2ray
				break
				;;
			2)
				stop_v2ray
				break
				;;
			3)
				restart_v2ray
				break
				;;
			4)
				view_v2ray_log
				break
				;;
			5)
				view_v2ray_error_log
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
start_v2ray() {
	if [[ $v2ray_pid ]]; then
		echo
		echo -e "${green} V2Ray is running $none"
		echo
	else

		# systemctl start v2ray
		service v2ray start >/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			echo
			echo -e "${red} V2Ray start failed $none"
			echo
		else
			echo
			echo -e "${green} V2Ray started $none"
			echo
		fi

	fi
}
stop_v2ray() {
	if [[ $v2ray_pid ]]; then
		# systemctl stop v2ray
		service v2ray stop >/dev/null 2>&1
		echo
		echo -e "${green} V2Ray stopped $none"
		echo
	else
		echo
		echo -e "${red} V2Ray not running $none"
		echo
	fi
}
restart_v2ray() {
	# systemctl restart v2ray
	service v2ray restart >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo
		echo -e "${red} V2Ray restart failed！$none"
		echo
	else
		echo
		echo -e "${green} V2Ray restart finish $none"
		echo
	fi
}
view_v2ray_log() {
	echo
	echo -e "$green type Ctrl + C exit...$none"
	echo
	tail -f /var/log/v2ray/access.log
}
view_v2ray_error_log() {
	echo
	echo -e "$green type Ctrl + C exit...$none"
	echo
	tail -f /var/log/v2ray/error.log
}
download_v2ray_config() {
	while :; do
		echo
		echo -e "$yellow 1. $none down V2Ray client config(only support Xshell)"
		echo
		echo -e "$yellow 2. $none gen V2Ray client config download url"
		echo
		echo -e "$yellow 3. $none gen V2Ray config url"
		echo
		echo -e "$yellow 4. $none gen V2Ray config QR"
		echo
		read -p "$(echo -e "choose [${magenta}1-4$none]:")" other_opt
		if [[ -z $other_opt ]]; then
			error
		else
			case $other_opt in
			1)
				get_v2ray_config
				break
				;;
			2)
				get_v2ray_config_link
				break
				;;
			3)
				get_v2ray_config_info_link
				break
				;;
			4)
				get_v2ray_config_qr_link
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
get_v2ray_config() {
	config
	echo
	echo " 如果你current使用的 SSH 客户端不是 Xshell 的话...下载 V2Ray 客户端配置文件将会出现卡死情况"
	echo
	while :; do
		read -p "$(echo -e "不要BB...哥就是在使用 Xshell [${magenta}Y$none]:")" is_xshell
		if [[ -z $is_xshell ]]; then
			error
		else
			if [[ $is_xshell == [yY] ]]; then
				echo
				echo "downloading....请选择 V2Ray 客户端配置文件保存位置"
				echo
				# sz /etc/v2ray/233blog_v2ray.zip
				local tmpfile="/tmp/233blog_v2ray_config_$RANDOM.json"
				cp -f $v2ray_client_config $tmpfile
				sz $tmpfile
				echo
				echo
				echo -e "$green finish...$none"
				echo
				# echo -e "$yellow 解压密码 = ${cyan}233blog.com$none"
				# echo
				echo -e "$yellow SOCKS listen port = ${cyan}2333${none}"
				echo
				echo -e "${yellow} HTTP listen port = ${cyan}6666$none"
				echo
				echo "V2Ray 客户端使用教程: https://233v2.com/post/4/"
				echo
				break
			else
				error
			fi
		fi
	done
	[[ -f $tmpfile ]] && rm -rf $tmpfile

}
get_v2ray_config_link() {
	_load client_file.sh
	_get_client_file
}
create_v2ray_config_text() {

	get_transport_args

	echo
	echo
	echo "---------- V2Ray 配置信息 -------------"
	if [[ $v2ray_transport == [45] ]]; then
		if [[ ! $caddy ]]; then
			echo
			echo " 警告！请自行配置 TLS...教程: https://233v2.com/post/3/"
		fi
		echo
		echo "地址 (Address) = ${domain}"
		echo
		echo " port (Port) = 443"
		echo
		echo "用户ID (User ID / UUID) = ${v2ray_id}"
		echo
		echo "额外ID (Alter Id) = ${alterId}"
		echo
		echo " transfer protocol (Network) = ${net}"
		echo
		echo "伪装类型 (header type) = ${header}"
		echo
		echo "伪装域名 (host) = ${domain}"
		echo
		echo "路径 (path) = ${_path}"
		echo
		echo "底层传输安全 (TLS) = tls"
		echo
		if [[ $ban_ad ]]; then
			echo " 备注: 广告拦截已开启.."
			echo
		fi
	elif [[ $v2ray_transport == 33 ]]; then
		echo
		echo '---提示..这是 VLESS 服务器配置---'
		echo
		echo "地址 (Address) = ${domain}"
		echo
		echo " port (Port) = 443"
		echo
		echo "用户ID (User ID / UUID) = ${v2ray_id}"
		echo
		echo "流控 (Flow) = 空"
		echo
		echo "加密 (Encryption) = none"
		echo
		echo " transfer protocol (Network) = ${net}"
		echo
		echo "伪装类型 (header type) = ${header}"
		echo
		echo "伪装域名 (host) = ${domain}"
		echo
		echo "路径 (path) = ${_path}"
		echo
		echo "底层传输安全 (TLS) = tls"
		echo
		if [[ $ban_ad ]]; then
			echo " 备注: 广告拦截已开启.."
			echo
		fi
	else
		[[ -z $ip ]] && get_ip
		echo
		echo "地址 (Address) = ${ip}"
		echo
		echo " port (Port) = $v2ray_port"
		echo
		echo "用户ID (User ID / UUID) = ${v2ray_id}"
		echo
		echo "额外ID (Alter Id) = ${alterId}"
		echo
		echo " transfer protocol (Network) = ${net}"
		echo
		echo "伪装类型 (header type) = ${header}"
		echo
	fi
	if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]] && [[ $ban_ad ]]; then
		echo "备注: dynamic port enable...ad block enable..."
		echo
	elif [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
		echo "备注: dynamic port enable..."
		echo
	elif [[ $ban_ad ]]; then
		echo "备注: ad block enable.."
		echo
	fi
	echo "---------- END -------------"
	echo
	echo "V2Ray 客户端使用教程: https://233v2.com/post/4/"
	echo
}
get_v2ray_config_info_link() {
	echo
	echo -e "$green gen.... wait....$none"
	echo
	create_v2ray_config_text >/tmp/233blog_v2ray.txt
	local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link=$(curl -s --upload-file /tmp/233blog_v2ray.txt "https://transfer.sh/${random}_233v2_v2ray.txt")
	if [[ $link ]]; then
		echo
		echo "---------- V2Ray 配置信息链接-------------"
		echo
		echo -e "$yellow url = $cyan$link$none"
		echo
		echo -e " V2Ray 客户端使用教程: https://233v2.com/post/4/"
		echo
		echo "备注...链接将在 14 天后失效..."
		echo
		echo "提醒...请不要把链接分享出去...除非你有特别的理由...."
		echo
	else
		echo
		echo -e "$red 哎呀呀呀...出错咯...请重试$none"
		echo
	fi
	rm -rf /tmp/233blog_v2ray.txt
}
get_v2ray_config_qr_link() {

	create_vmess_URL_config

	_load qr.sh
	_qr_create
}
get_v2ray_vmess_URL_link() {
	create_vmess_URL_config
	if [[ $v2ray_transport == 33 ]]; then
		local vmess="$(cat /etc/v2ray/vmess_qr.json)"
	else
		local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
	fi
	echo
	echo "---------- V2Ray vmess URL / V2RayNG v0.4.1+ / V2RayN v2.1+ / 仅适合部分客户端 -------------"
	echo
	echo -e ${cyan}$vmess${none}
	echo
	echo -e "${yellow}免被墙..推荐使用JMS: ${cyan}https://getjms.com${none}"
	echo
	rm -rf /etc/v2ray/vmess_qr.json
}
other() {
	while :; do
		echo
		echo -e "$yellow 1. $none install BBR"
		echo
		read -p "$(echo -e "choose [${magenta}1$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				install_bbr
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
install_bbr() {
	local test1=$(sed -n '/net.ipv4.tcp_congestion_control/p' /etc/sysctl.conf)
	local test2=$(sed -n '/net.core.default_qdisc/p' /etc/sysctl.conf)
	if [[ $test1 == "net.ipv4.tcp_congestion_control = bbr" && $test2 == "net.core.default_qdisc = fq" ]]; then
		echo
		echo -e "$green BBR enabled...no need to install $none"
		echo
	else
		_load bbr.sh
		_try_enable_bbr
		[[ ! $enable_bbr ]] && bash <(curl -s -L https://github.com/teddysun/across/raw/master/bbr.sh)
	fi
}

update() {
	while :; do
		echo
		echo -e "$yellow 1. $none update V2Ray main program"
		echo
		echo -e "$yellow 2. $none update V2Ray manage"
		echo
		read -p "$(echo -e "choose [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				update_v2ray
				break
				;;
			2)
				update_v2ray.sh
				exit
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
update_v2ray() {
	_load download-v2ray.sh
	_update_v2ray_version
}
update_v2ray.sh() {
	if [[ $_test ]]; then
		local latest_version=$(curl -H 'Cache-Control: no-cache' -s -L "https://raw.githubusercontent.com/233boy/v2ray/test/v2ray.sh" | grep '_version' -m1 | cut -d\" -f2)
	else
		local latest_version=$(curl -H 'Cache-Control: no-cache' -s -L "https://raw.githubusercontent.com/233boy/v2ray/master/v2ray.sh" | grep '_version' -m1 | cut -d\" -f2)
	fi

	if [[ ! $latest_version ]]; then
		echo
		echo -e " $red获取 V2Ray 最新版本失败!!!$none"
		echo
		echo -e " 请尝试执行如下命令: $green echo 'nameserver 8.8.8.8' >/etc/resolv.conf $none"
		echo
		echo " 然后再继续...."
		echo
		exit 1
	fi

	if [[ $latest_version == $_version ]]; then
		echo
		echo -e "$green 木有发现新版本 $none"
		echo
	else
		echo
		echo -e " $green 咦...发现新版本耶....正在拼命更新.......$none"
		echo
		cd /etc/v2ray/233boy/v2ray
		git pull
		cp -f /etc/v2ray/233boy/v2ray/v2ray.sh $_v2ray_sh
		chmod +x $_v2ray_sh
		echo
		echo -e "$green update success...current V2Ray manage level 版本: ${cyan}$latest_version$none"
		echo
	fi

}
uninstall_v2ray() {
	_load uninstall.sh
}
config() {
	_load config.sh

	if [[ $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd >/dev/null 2>&1
			[[ $(command -v httpd) ]] && yum remove httpd -y >/dev/null 2>&1
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop >/dev/null 2>&1
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y >/dev/null 2>&1
		fi
	fi
	do_service restart v2ray
}
backup_config() {
	for keys in $*; do
		case $keys in
		v2ray_transport)
			sed -i "18s/=$v2ray_transport/=$v2ray_transport_opt/" $backup
			;;
		v2ray_port)
			sed -i "21s/=$v2ray_port/=$v2ray_port_opt/" $backup
			;;
		uuid)
			sed -i "24s/=$v2ray_id/=$uuid/" $backup
			;;
		alterId)
			sed -i "27s/=$alterId/=$new_alterId/" $backup
			;;
		v2ray_dynamicPort_start)
			sed -i "30s/=$v2ray_dynamicPort_start/=$v2ray_dynamic_port_start_input/" $backup
			;;
		v2ray_dynamicPort_end)
			sed -i "33s/=$v2ray_dynamicPort_end/=$v2ray_dynamic_port_end_input/" $backup
			;;
		domain)
			sed -i "36s/=$domain/=$new_domain/" $backup
			;;
		caddy)
			sed -i "39s/=/=true/" $backup
			;;
		+ss)
			sed -i "42s/=/=true/; 45s/=$ssport/=$new_ssport/; 48s/=$sspass/=$new_sspass/; 51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		-ss)
			sed -i "42s/=true/=/" $backup
			;;
		ssport)
			sed -i "45s/=$ssport/=$new_ssport/" $backup
			;;
		sspass)
			sed -i "48s/=$sspass/=$new_sspass/" $backup
			;;
		ssciphers)
			sed -i "51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		+ad)
			sed -i "54s/=/=true/" $backup
			;;
		-ad)
			sed -i "54s/=true/=/" $backup
			;;
		+path)
			sed -i "57s/=/=true/; 60s/=$path/=$new_path/; 63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		-path)
			sed -i "57s/=true/=/" $backup
			;;
		path)
			sed -i "60s/=$path/=$new_path/" $backup
			;;
		proxy_site)
			sed -i "63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		+socks)
			sed -i "66s/=/=true/; 69s/=$socks_port/=$new_socks_port/; 72s/=$socks_username/=$new_socks_username/; 75s/=$socks_userpass/=$new_socks_userpass/;" $backup
			;;
		-socks)
			sed -i "66s/=true/=/" $backup
			;;
		socks_port)
			sed -i "69s/=$socks_port/=$new_socks_port/" $backup
			;;
		socks_username)
			sed -i "72s/=$socks_username/=$new_socks_username/" $backup
			;;
		socks_userpass)
			sed -i "75s/=$socks_userpass/=$new_socks_userpass/" $backup
			;;
		+mtproto)
			sed -i "78s/=/=true/; 81s/=$mtproto_port/=$new_mtproto_port/; 84s/=$mtproto_secret/=$new_mtproto_secret/" $backup
			;;
		-mtproto)
			sed -i "78s/=true/=/" $backup
			;;
		mtproto_port)
			sed -i "81s/=$mtproto_port/=$new_mtproto_port/" $backup
			;;
		mtproto_secret)
			sed -i "84s/=$mtproto_secret/=$new_mtproto_secret/" $backup
			;;
		+bt)
			sed -i "87s/=/=true/" $backup
			;;
		-bt)
			sed -i "87s/=true/=/" $backup
			;;
		esac
	done

}

get_ip() {
	ip=$(curl -s https://ipinfo.io/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	[[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	[[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	[[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && echo -e "\n$red 这垃圾小鸡扔了吧！$none\n" && exit
}

error() {

	echo -e "\n$red input error！$none\n"

}

pause() {

	read -rsp "$(echo -e "type $green Enter  $none continue....or type $red Ctrl + C $none cancel.")" -d $'\n'
	echo
}
do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
_help() {
	echo
	echo "........... V2Ray 管理脚本帮助信息 by 233v2.com .........."
	echo -e "
	${green}v2ray menu $none manage V2Ray (equal to v2ray)

	${green}v2ray info $none view V2Ray config

	${green}v2ray config $none update  V2Ray 配置

	${green}v2ray link $none生成 V2Ray 客户端配置文件链接

	${green}v2ray textlink $none生成 V2Ray 配置信息链接

	${green}v2ray qr $none生成 V2Ray 配置二维码链接

	${green}v2ray ss $none update  Shadowsocks 配置

	${green}v2ray ssinfo $none查看 Shadowsocks 配置信息

	${green}v2ray ssqr $none生成 Shadowsocks 配置二维码链接

	${green}v2ray status $none查看 V2Ray 运行状态

	${green}v2ray start $none启动 V2Ray

	${green}v2ray stop $none停止 V2Ray

	${green}v2ray restart $none重启 V2Ray

	${green}v2ray log $none查看 V2Ray 运行日志

	${green}v2ray update $none更新 V2Ray

	${green}v2ray update.sh $none更新 V2Ray 管理脚本

	${green}v2ray uninstall $none卸载 V2Ray
"
}
menu() {
	clear
	while :; do
		echo
		echo "........... V2Ray 管理脚本 $_version by 233v2.com .........."
		echo
		echo -e "## V2Ray 版本: $cyan$v2ray_ver$none  /  V2Ray 状态: $v2ray_status ##"
		echo
		echo "帮助说明: https://233v2.com/post/1/"
		echo
		echo "反馈问题: https://github.com/233boy/v2ray/issues"
		echo
		echo "TG 频道: https://t.me/tg2333"
		echo
		echo "捐赠脚本作者: https://233v2.com/donate/"
		echo
		echo "捐助 V2Ray: https://www.v2ray.com/chapter_00/02_donate.html"
		echo
		echo -e "$yellow  1. $none view V2Ray config"
		echo
		echo -e "$yellow  2. $none update V2Ray config"
		echo
		echo -e "$yellow  3. $none download V2Ray config / gen config url / gen config QR"
		echo
		echo -e "$yellow  4. $none view Shadowsocks config / gen config QR"
		echo
		echo -e "$yellow  5. $none update Shadowsocks config"
		echo
		echo -e "$yellow  6. $none view MTProto config / update MTProto config"
		echo
		echo -e "$yellow  7. $none view Socks5 config / update Socks5 config"
		echo
		echo -e "$yellow  8. $none start / stop / restart / check log"
		echo
		echo -e "$yellow  9. $none update V2Ray / update V2Ray manager"
		echo
		echo -e "$yellow 10. $none uninstall V2Ray"
		echo
		echo -e "$yellow 11. $none other"
		echo
		echo -e "...$yellow Ctrl + C $none quit"
		echo
		read -p "$(echo -e "choose: [${magenta}1-11$none]:")" choose
		if [[ -z $choose ]]; then
			exit 1
		else
			case $choose in
			1)
				view_v2ray_config_info
				break
				;;
			2)
				change_v2ray_config
				break
				;;
			3)
				download_v2ray_config
				break
				;;
			4)
				get_shadowsocks_config
				break
				;;
			5)
				change_shadowsocks_config
				break
				;;
			6)
				_load mtproto.sh
				_mtproto_main
				break
				;;
			7)
				_load socks.sh
				_socks_main
				break
				;;
			8)
				v2ray_service
				break
				;;
			9)
				update
				break
				;;
			10)
				uninstall_v2ray
				break
				;;
			11)
				other
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
args=$1
[ -z $1 ] && args="menu"
case $args in
menu)
	menu
	;;
i | info)
	view_v2ray_config_info
	;;
c | config)
	change_v2ray_config
	;;
l | link)
	get_v2ray_config_link
	;;
L | infolink)
	get_v2ray_config_info_link
	;;
q | qr)
	get_v2ray_config_qr_link
	;;
s | ss)
	change_shadowsocks_config
	;;
S | ssinfo)
	view_shadowsocks_config_info
	;;
Q | ssqr)
	get_shadowsocks_config_qr_link
	;;
socks)
	_load socks.sh
	_socks_main
	;;
socksinfo)
	_load socks.sh
	_view_socks_info
	;;
tg)
	_load mtproto.sh
	_mtproto_main
	;;
tginfo)
	_load mtproto.sh
	_view_mtproto_info
	;;
bt)
	_load bt.sh
	_ban_bt_main
	;;
status)
	echo
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		echo -e " V2Ray status: $v2ray_status  /  Caddy status: $caddy_run_status"
	else
		echo -e " V2Ray status: $v2ray_status"
	fi
	echo
	;;
start)
	start_v2ray
	;;
stop)
	stop_v2ray
	;;
restart)
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		do_service restart caddy
	fi
	restart_v2ray
	;;
reload)
	config
	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && [[ $caddy ]]; then
		caddy_config
	fi
	clear
	view_v2ray_config_info
	;;
time)
	date -s "$(curl -sI g.cn | grep Date | cut -d' ' -f3-6)Z"
	;;
log)
	view_v2ray_log
	;;
url | URL)
	get_v2ray_vmess_URL_link
	;;
u | update)
	update_v2ray
	;;
U | update.sh)
	update_v2ray.sh
	exit
	;;
un | uninstall)
	uninstall_v2ray
	;;
reinstall)
	uninstall_v2ray
	if [[ $is_uninstall_v2ray ]]; then
		cd
		cd - >/dev/null 2>&1
		bash <(curl -s -L https://git.io/v2ray.sh)
	fi
	;;
[aA][Ii] | [Dd])
	change_v2ray_alterId
	;;
[aA][Ii][aA][Ii] | [Dd][Dd] | aid)
	custom_uuid
	;;
reuuid)
	backup_config uuid
	v2ray_id=$uuid
	config
	clear
	view_v2ray_config_info
	# download_v2ray_config_ask
	;;
v | version)
	echo
	echo -e "V2Ray version: ${green}$v2ray_ver$none  /  V2Ray manager version: ${cyan}$_version$none"
	echo
	;;
bbr)
	other
	;;
help | *)
	_help
	;;
esac
