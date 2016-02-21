#!/bin/bash
#
# Shell Script - Firewall
# Testado em Debian 7 Wheezy, Debian 8 Jessie, CentOS 7/RHEL7 e Slackware 14.1
# =======================
# Matheus Fidelis | Nanoshots - Open Source Security
# 2015-08-22
#
# Testado na inicialização do sistema 

echo -e "\033[01;37m"

# Variaveis
# Não implementado
inet=$1
ipt=/sbin/iptables
network="192.168.0.0/24"
ip="192.168.0.202"
 
function CarregaModulos(){
echo -n "Carregando módulos ............................................"
 # Carrega os módulos
 modprobe ip_tables
 #modproble iptable_nat
}

function LimpaRegras(){
echo -n "Limpando regras ..............................................."
 # Limpando as Chains
 iptables -F INPUT
 iptables -F OUTPUT
 iptables -F FORWARD
 iptables -F -t filter
 iptables -F POSTROUTING -t nat
 iptables -F PREROUTING -t nat
 iptables -F OUTPUT -t nat
 iptables -F -t nat
 iptables -t nat -F
 iptables -t mangle -F
 iptables -X
 # Zerando contadores
 iptables -Z
 iptables -t nat -Z
 iptables -t mangle -Z
 # Define politicas padrao ACCEPT
 iptables -P INPUT ACCEPT
 iptables -P OUTPUT ACCEPT
 iptables -P FORWARD ACCEPT
}

function PoliticaPadrao(){
 echo -n "Definindo politica padrão ....................................."
 # Define a politica padrao de cada chain
 iptables -P INPUT DROP
 iptables -P OUTPUT ACCEPT
 iptables -P FORWARD DROP
}

function CriaChain(){
 echo -n "Criando chains ................................................"
 # iptables -N LOGADO
}

function LiberaLoopback(){
 echo -n "Liberando loopback ............................................"
 iptables -A INPUT -i lo -d 127.0.0.1 -j ACCEPT
 # A potítica padrão da chain OUTPUT já é ACCEPT
 # iptables -A OUTPUT -o lo -d 127.0.0.1 -j ACCEPT
}

function LiberaConexoes(){
 echo -n "Liberando conexões ............................................"
 # Liberar Conexões Estabelecidas
 iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
 # Liberar o ping da propria máquina para a sua placa de rede
 # iptables -A INPUT -p icmp -s $ip -j ACCEPT
}

function LiberaPortas(){
 echo -n "Liberando portas .............................................."
 # iptables -A INPUT -p tcp --dport 80 -j ACCEPT
}

function Protecao(){
 echo -n "Aplicando regras de proteção .................................."
 i=/proc/sys/net/ipv4
 # Desabilita o trafego IP entre as placas de rede
 echo "0" > /proc/sys/net/ipv4/ip_forward
 # Protecao contra SYN flood
 echo "1" > $i/tcp_syncookies
 echo "1" > $i/icmp_echo_ignore_broadcasts
 # Protecao contra responses bogus
 echo "1" > $i/icmp_ignore_bogus_error_responses
 
 for i in /proc/sys/net/ipv4/conf/*; do
   # Impedir que um atacante possa maliciosamente alterar alguma rota
   echo "0" > $i/accept_redirects
   # Utilizado em diversos ataques, isso possibilita que o atacante 
   # determine o "caminho" que seu pacote vai percorrer (roteadores)
   # ate seu destino.
   echo "0" > $i/accept_source_route
   echo "1" > $i/log_martians
   # Configurando a Protecao anti-spoofing
   echo "1" > $i/rp_filter
 done

 # Proteção contra Ataques - Registra no LOG do sistema
 iptables -I INPUT 1 -m state --state INVALID -j LOG --log-level info --log-prefix "PKT INVALIDO - "
 iptables -I INPUT 2 -m state --state INVALID -j DROP
 
 # Proteção contra os "Ping of Death"
 # Na configuração padrão do script todos as respostas aos PINGs foram desativadas
 #
 # iptables -A INPUT -i $inet -p  --icmp-type 8 -m limit --limit 5/m -j DROP
 # iptables -A INPUT -i $inet -p  --icmp-type 0 -j ACCEPT
 # iptables -A INPUT -i $ilan -p -j ACCEPT
 
 # Proteção contra Port Scanner NMAP
 iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 5/m -j ACCEPT
}

function Servidores(){
 echo -n "Liberando conexão de entrada nos servidores ..................."
    #DESCOMENTE DE ACORDO COM AS NECESSIDADES DO SERVIDOR
    # Apache - Servidor Web
    #iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEP -h' or 'iptables --help' for more information.
  
    # Apache TomCat - Servidor Web
    #iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
    
    #Servidor MySQL
    #iptables -A INPUT -p tcp --dport 3306 -j ACCEPT 
  	 
    # Bind - Servidor DNS
    #iptables -A INPUT -p udp --dport 53 -j ACCEPT
 
    # DanGuardian - Servidor Proxy
    #iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
 
    # ProFTP - Servidor FTP
    #iptables -A INPUT -p tcp --dport 21 -j ACCEPT
    #iptables -A INPUT -p tcp -m multiport --dports 49152:49162 -j ACCEPT
 
    # Postfix - Servidor de E-mail
    #iptables -A INPUT -i $ilan -p tcp -m multiport --dports 25,110 -j ACCEPT
    #iptables -A INPUT -i $ilan -p tcp -m multiport --dports 465,995 -j ACCEPT
    #iptables -A INPUT -i $ilan -p tcp --sport 25 -j ACCEPT
 
    # PostgreSQL - Servidor Postgresql
    #iptables -A INPUT -i $ilan -p tcp --dport 5432 -j ACCEPT
 
    # SSH - Servidor SSH
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
 
    # VNC - Servidor de Acesso Remoto
    iptables -A INPUT -p tcp --dport 5900 -j ACCEPT
 
    # PROTOCOLOS E SERVIÇOS #
 
    # AIM
    #iptables -A INPUT -i $inet -p tcp --sport 5190 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 5190 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 5190 -j ACCEPT
     
    # DNS - Serviço de Nomes de Dominios
    #iptables -A INPUT -p tcp -m multiport --sports 53,5353 -j ACCEPT
    #iptables -A INPUT -p udp -m multiport --sports 53,5353 -j ACCEPT
    #iptables -A FORWARD -p tcp -m multiport --sports 53,5353 -j ACCEPT
    #iptables -A FORWARD -p udp -m multiport --sports 53,5353 -j ACCEPT
    #iptables -A FORWARD -p tcp -m multiport --dports 53,5353 -j ACCEPT
    #iptables -A FORWARD -p udp -m multiport --dports 53,5353 -j ACCEPT
 
    # FTP - Protocolo de Transferência de Arquivo
    #iptables -A INPUT -i $inet -p tcp --sport 21 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 21 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 21 -j ACCEPT
 
    # HTTP - Protocolo de Transferência de Hypertext
    #iptables -A INPUT -i $inet -p tcp -m multiport --sports 80,8080 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp -m multiport --sports 80,8080 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp -m multiport --dports 80,8080 -j ACCEPT
 
    # HTTPS - Protocolo de Transferência de Hypertext Seguro
    #iptables -A INPUT -i $inet -p tcp --sport 443 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 443 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 443 -j ACCEPT
 
    # IAPP - Protocolo de Ponto de Acesso
    #iptables -A INPUT -i $ilan -p udp --sport 2313 -j ACCEPT
 
    # IPP - Protocolo de Impressão na Internet
    #iptables -A INPUT -i $ilan -p tcp --dport 631 -j ACCEPT
    #iptables -A INPUT -i $ilan -p udp -m multiport --dports 138,631 -j ACCEPT
 
    # IRC - Internet Relay Chat
    #iptables -A INPUT -i $inet -p tcp --sport 6667 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 6667 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 6667 -j ACCEPT
 
    # Microsoft-DS - Serviços de Diretório da Microsoft
    #iptables -A INPUT -i $ilan -p tcp --dport 445 -j ACCEPT
    #iptables -A INPUT -i $ilan -p tcp -m multiport --sports 139,445 -j ACCEPT
 
    # MSNMS - Serviço de Mensageiro de Rede da Microsoft
    #iptables -A INPUT -i $inet -p tcp -m multiport --sports 1863,1900 -j ACCEPT
    #iptables -A INPUT -i $inet -p udp --sport 1900 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp -m multiport --sports 1863,7001 -j ACCEPT
    #iptables -A FORWARD -i $inet -p udp --sport 7001 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp -m multiport --dports 1863,7001 -j ACCEPT
    #iptables -A FORWARD -o $inet -p udp --dport 7001 -j ACCEPT
 
    # NETBIOS-SSN - Serviço de Sessão NetBIOS
    #iptables -A INPUT -i $ilan -p udp -m multiport --dports 137,138 -j ACCEPT
    #iptables -A INPUT -i $ilan -p tcp --dport 139 -j ACCEPT
 
    # NO-IP - Provedor de DNS Dinâmico
    #iptables -A INPUT -i $inet -p tcp --sport 8245 -j ACCEPT
 
    # NTP - Protocolo para sincronização dos relógios
    #iptables -A INPUT -i $inet -p udp --sport 123 -j ACCEPT
    #iptables -A FORWARD -i $inet -p udp --sport 123 -j ACCEPT
    #iptables -A FORWARD -o $inet -p udp --dport 123 -j ACCEPT
 
    # POP3S - Protocolo de Correio Seguro
    #iptables -A INPUT -i $inet -p tcp --sport 995 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 995 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 995 -j ACCEPT
 
    # SSDP - Protocolo para Descoberta de Serviços Simples
    #iptables -A INPUT -i $ilan -p udp --dport 1900 -j ACCEPT
 
    # SSH - Shell Seguro
    iptables -A INPUT -p tcp --sport 22 -j ACCEPT
    iptables -A FORWARD -i $inet -p tcp --sport 22 -j ACCEPT
    iptables -A FORWARD -o $inet -p tcp --dport 22 -j ACCEPT
 
    # SSMTP - Protocolo Simples para Transferência de Correio Seguro
    #iptables -A INPUT -i $inet -p tcp -m multiport --sports 465,587 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 465 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 465 -j ACCEPT
 
    # TELNET
    #iptables -A INPUT -p tcp --sport 23 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 23 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 23 -j ACCEPT
 
    # VNC - Computação em Rede Virtual
    iptables -A INPUT -p tcp --sport 5900 -j ACCEPT
    iptables -A FORWARD -i $inet -p tcp --sport 5900 -j ACCEPT
    iptables -A FORWARD -o $inet -p tcp --dport 5900 -j ACCEPT
 
    # XMPP - Protocolo de Presença e Mensagens Extensiva
    #iptables -A INPUT -i $inet -p tcp --sport 5222 -j ACCEPT
    #iptables -A FORWARD -i $inet -p tcp --sport 5222 -j ACCEPT
    #iptables -A FORWARD -o $inet -p tcp --dport 5222 -j ACCEPT
}

function AtivaPing(){
 echo -n "Ativando resposta do ping ....................................."
 echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all
}

function DesativaPing(){
 echo -n "Desativando resposta do ping .................................."
 echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all
}

function DesativaProtecao(){
 echo -n "Removendo regras de proteção .................................."
 i=/proc/sys/net/ipv4
 echo "1" > /proc/sys/net/ipv4/ip_forward
 echo "0" > $i/tcp_syncookies
 echo "0" > $i/icmp_echo_ignore_broadcasts
 echo "0" > $i/icmp_ignore_bogus_error_responses
 for i in /proc/sys/net/ipv4/conf/*; do
   echo "1" > $i/accept_redirects
   echo "1" > $i/accept_source_route
   echo "0" > $i/log_martians
   echo "0" > $i/rp_filter
 done
}

function IniciaFirewall(){
 echo "THE LITTLE WAF - MATHEUS FIDELIS - CARREGANDO..."
 echo
  if CarregaModulos
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if LimpaRegras
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if PoliticaPadrao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if CriaChain
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if LiberaLoopback
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if LiberaConexoes
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if LiberaPortas
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if Protecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if DesativaPing
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if Servidores
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 # Lista de Funções executadas
 #LimpaRegras
 #PoliticaPadrao
 #CriaChain
 #LiberaLoopback
 #LiberaConexoes
 #LiberaPortas
 #Protecao
 #DesativaPing
 #Servidores
 echo
}

function ParaFirewall(){
 echo "THE LITTLE WAF - MATHEUS FIDELIS"
 echo
 if LimpaRegras
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if AtivaPing
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if DesativaProtecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 # Lista de Funções executadas
 #LimpaRegras
 #AtivaPing
 #DesativaProtecao
 echo
}

function ReiniciaFirewall(){
 echo "THE LITTLE WAF - MATHEUS FIDELIS REINICIANDO..."
 echo
 ParaFirewall
 IniciaFirewall
 echo
}

case $1 in
  start)
   IniciaFirewall
   exit 0
  ;;

  stop)
   ParaFirewall
  ;;

  restart)
   ReiniciaFirewall
  ;;

  -l)
   iptables -L -nv --line-numbers
  ;;

  ativaping)
   if AtivaPing
  	then
   	  echo -e "[\033[01;32m  OK  \033[01;37m]"
  	else
   	  echo -e "[\033[01;31m  Erro  \033[01;37m]"
   fi
   #AtivaPing
  ;;

  desativaping)
   if DesativaPing
	then
	   echo -e "[\033[01;32m  OK  \033[01;37m]"
	else
	   echo -e "[\033[01;31m  Erro  \033[01;37m]"
   fi
 #DesativaPing
  ;;

  *)
   echo "Escolha uma opção válida { start | stop | restart | ativaping | desativaping | -l }"
   echo
esac

# Outras opções úteis AINDA não adicionadas por falta de testes

# PROTEÇÃO CONTRA PACOTES QUEBRADOS 
iptables -A FORWARD -m unclean -j DROP

# Compartilha a conexão (IP Masquerading)
#modprobe iptable_nat
#iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
#echo "1" > /proc/sys/net/ipv4/ip_forward

# Abre para a rede local

#iptables -A INPUT -p tcp --syn -s 192.168.0.0 -j ACCEPT
#iptables -A INPUT -p tcp --syn -s 192.168.0.0 -j ACCEPT
#iptables -A OUTPUT -p tcp --syn -s 192.168.0.0/255.255.255.0 -j ACCEPT

# Para registrar os pacotes ICMP no LOG do sistema /var/log/messages
 iptables -A LOGADO -j LOG --log-level info --log-prefix "ICMP Registrado - "
 #iptables -I OUTPUT 1 -d 127.0.0.1 -p icmp -j LOGADO
