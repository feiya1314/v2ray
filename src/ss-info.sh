[[ -z $ip ]] && get_ip
if [[ $shadowsocks ]]; then
	local ss="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#233v2.com_ss_${ip}"
	echo
	echo "---------- Shadowsocks 配置信息 -------------"
	echo
	echo -e "$yellow 服务器地址(address) = $cyan${ip}$none"
	echo
	echo -e "$yellow 服务器端口(port) = $cyan$ssport$none"
	echo
	echo -e "$yellow 密码(password) = $cyan$sspass$none"
	echo
	echo -e "$yellow 加密协议(encrypt protocol) = $cyan${ssciphers}$none"
	echo
	echo -e "$yellow SS 链接(url) = ${cyan}$ss$none"
	echo
	echo -e " 备注: $red Shadowsocks Win 4.0.6 $none 客户端可能无法识别该 SS 链接"
	echo
	echo -e "提示: input $cyan v2ray ssqr $none to gen Shadowsocks QR"	
	echo
	echo -e "${yellow}免被墙..推荐使用JMS: ${cyan}https://getjms.com${none}"
	echo
fi
