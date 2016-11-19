#######################################################
##             Simple ROCK Build Recipe              ##
##               Provided by MOCYBER                 ##
#######################################################

log 'branding' do
  message '
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                       Thank you for installing:                              │
│                                                                              │
│                                                                              │
│                 :::::::..       ...       .,-:::::  :::  .                   │
│                 ;;;;``;;;;   .;;;;;;;.  ,;;;\'````\'  ;;; .;;,.                │
│                  [[[,/[[[\'  ,[[     \[[,[[[         [[[[[/\'                  │
│                  $$$$$$c    $$$,     $$$$$$        _$$$$,                    │
│                  888b "88bo,"888,_ _,88P`88bo,__,o,"888"88o,                 │
│                  MMMM   "W"   "YMMMMMP"   "YUMMMMMP"MMM "MMP"                │
│                          :::.    :::. .::::::. .        :                    │
│                          `;;;;,  `;;;;;;`    ` ;;,.    ;;;                   │
│                            [[[[[. \'[[\'[==/[[[[,[[[[, ,[[[[,                  │
│                            $$$ "Y$c$$  \'\'\'    $$$$$$$$$"$$$                  │
│                            888    Y88 88b    dP888 Y88" 888o                 │
│                            MMM     YM  "YMmMY" MMM  M\'  "MMM                 │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
'
  level :warn
  action :nothing
end

#######################################################
################# OS & Version Check ##################
#######################################################
## DEBUG
Chef::Log.debug(node['platform_family'])
Chef::Log.debug(node['platform_version'])

if node['platform_family'] != 'rhel'
  Chef::Log.fatal('This Cookbook is only meant for RHEL/CENTOS 7')
end

# Die if it's not CentOS/RHEL 7
raise if node['platform_family'] != 'rhel'
raise if not node['platform_version'] =~ /^7./

######################################################
################# Data Directory #####################
######################################################

###############
##### NOTE ####
###############
#You will want to remount this to your "good" storage after the build.  This is just to make sure all the paths in the configs are proper.
###############
directory '/data' do
  mode '0755'
  owner 'root'
  group 'root'
  action :create
end

#######################################################
##################### Memory Info #####################
#######################################################
## Grab memory total from Ohai
total_memory = node['memory']['total']

## Ohai reports node[:memory][:total] in kB, as in "921756kB"
mem = total_memory.split("kB")[0].to_i / 1048576 # in GB

# Let's set a sane default in case ohai has decided to screw us.
node.run_state['es_mem'] = 4

if mem < 64
  # For systems with less than 32GB of system memory, we'll use half for Elasticsearch
  node.run_state['es_mem'] = mem / 2
else
  # Elasticsearch recommends not using more than 32GB for Elasticearch
  node.run_state['es_mem'] = 32
end

# We'll use es_mem later to do a "best effort" elasticsearch configuration

#######################################################
####################### CPU Info ######################
#######################################################
## Grab cpu total from Ohai
total_cpu = node['cpu']['total']

# Let's set a sane default in case ohai has decided to screw us.
node.run_state['bro_cpu'] = 2

if total_cpu <= 16
  # We'll use half the CPU's for bro, up to 8.
  node.run_state['bro_cpu'] = total_cpu / 2
else
  # I don't know what 64 bro processes run like, and I don't want to find out by surprise. We'll max at 8.
  node.run_state['bro_cpu'] = 8
end
#We'll use this in the bro node.cfg later.

######################################################
################### Configure Time ###################
######################################################
package 'chrony' do
  action :install
end

execute 'set_time_zone' do
  command '/usr/bin/timedatectl set-timezone UTC'
  not_if '/usr/bin/timedatectl | grep -q "Time zone.*UTC"'
end

execute 'enable_ntp' do
  command '/usr/bin/timedatectl set-ntp yes'
  not_if '/usr/bin/timedatectl | grep -q "NTP enabled.*yes"'
end

######################################################
############### Install Kernel Headers ###############
######################################################
## Necessary to make this pig run on RHEL:
['rhel-7-server-optional-rpms', 'rhel-7-server-extras-rpms'].each do |repo|
  execute "enable_#{repo}" do
    command "subscription-manager repos --enable #{repo}"
    only_if { platform?('rhel') }
    not_if "subscription-manager repos --list-enabled | grep -q #{repo}"
  end
end

execute 'enable_centos_cr' do
  command 'sed -i "s/enabled=0/enabled=1/g" /etc/yum.repos.d/CentOS-CR.repo'
  only_if { platform?('centos') }
end

fullver = node['kernel']['release']
kernver = fullver.sub(".#{node['kernel']['machine']}", '')

package "kernel-devel" do
  version "#{kernver}"
  arch "#{node['kernel']['machine']}"
end

package "kernel-headers" do
  version "#{kernver}"
  arch "#{node['kernel']['machine']}"
end

######################################################
######### Determine the monitoring interface #########
######################################################
ohai "reload_network" do
  action :nothing
  plugin "network"
end

ruby_block 'determine_monitor_interface' do
  action :nothing
  block do
    node['network']['interfaces'].each do |iface, vals|
      next unless vals[:encapsulation].match('Ethernet')
      Chef::Log.debug("DEBUG #{iface}: Addr length of #{vals[:addresses].length}\n#{vals[:addresses]}")
      next if iface == 'lo'
      next if iface == node['network']['default_interface']
      #next unless vals[:addresses].length == 1
      node.run_state['monif'] = iface
      ## DEBUG
      Chef::Log.debug("Using interface #{iface} for monitoring. \nDEBUG: Addr length of #{vals[:addresses].length}\n#{vals[:addresses]}")
      #Chef::Log.info("******** Using #{iface} (VAR: #{node.run_state['monif']}) for monitoring. ********")
    end
  end
  notifies :create, "template[ifcfg-monif]", :delayed
  notifies :create, "template[/sbin/ifup-local]", :delayed
  notifies :create, "template[/etc/stenographer/config]", :delayed
  notifies :create, "template[/etc/sysconfig/snort]", :delayed
  notifies :create, "template[/opt/bro/etc/node.cfg]", :delayed
end

#######################################################
#################### Disable IPv6 #####################
#######################################################
if File.readlines("/proc/sys/net/ipv6/conf/all/disable_ipv6").grep(/0/).size > 0 || File.readlines("/proc/sys/net/ipv6/conf/default/disable_ipv6").grep(/0/).size > 0

  execute 'ipv6_permanent_disable_1' do
    command 'echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf'
  end

  execute 'ipv6_permanent_disable_2' do
    command 'echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf'
  end

  execute 'ipv6_permanent_disable_3' do
    command 'sysctl -p'
  end

  execute 'ipv6_ephemeral_disable_all' do
    command 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
  end

  execute 'ipv6_ephemeral_disable_default' do
    command 'echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6'
  end

  execute 'ipv6_fix_sshd' do
    command 'sed -i "s/#AddressFamily any/AddressFamily inet/g" /etc/ssh/sshd_config'
  end

  execute 'ipv6_fix_sshd_restart' do
    command 'systemctl restart sshd'
  end

  execute 'ipv6_remove_localhost' do
    command 'sed -i "/^::1/d" /etc/hosts'
  end

  execute 'ipv6_fix_network_restart' do
    command 'systemctl restart network.service'
    notifies :reload, "ohai[reload_network]", :immediately
    notifies :run, resources("ruby_block[determine_monitor_interface]"), :delayed
  end
end

#######################################################
########### Add Monitor Interface File ################
#######################################################
template "ifcfg-monif" do
  path "/tmp/ifcfg_hacks.sh"
  source 'ifcfg_monif.erb'
  mode '0755'
  action :nothing
  notifies :run, "execute[ifcfg_hacks]", :delayed
end

execute 'ifcfg_hacks' do
  command "/tmp/ifcfg_hacks.sh"
  action :nothing
end

#Tune the capture interface, enable promiscuous mode at boot.
template "/sbin/ifup-local" do
 source 'ifup-local.erb'
 owner 'root'
 group 'root'
 mode '0755'
 action :nothing
end

#######################################################
###################### DNS Fixes ######################
#######################################################
# This is only necessary because my local DNS isn't trustworthy.
execute 'add_google_dns' do
  command 'echo "nameserver 8.8.8.8" > /etc/resolv.conf; echo "nameserver 8.8.4.4" >> /etc/resolv.conf'
  not_if 'grep 8.8.8.8 /etc/resolv.conf'
end

execute 'set_hostname' do
  command 'echo -e "127.0.0.2\tsimplerockbuild.simplerock.lan\tsimplerockbuild" >> /etc/hosts'
end

execute 'set_system_hostname' do
  command 'hostnamectl set-hostname simplerockbuild.simplerock.lan'
end

### TODO - This should come from somewhere else, not hard-coded.

#######################################################
#################### Install EPEL #####################
#######################################################
package 'epel-release' do
  action :install
  ignore_failure true
end

execute 'install_epel' do
  command 'rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm'
  not_if '[ $(rpm -qa epel-release | wc -l) -gt 0 ]'
end

execute 'import_epel_key' do
  command 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7'
  only_if '[ -f /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7 ]'
end

#######################################################
################ Install ROCK Repos ###################
#######################################################

packagecloud_repo "rocknsm/current" do
  type "rpm"
end


#######################################################
################ Install NTOP Repos ###################
#######################################################
# Commented out 19JAN16 - version 6.2.0-425 was built against Myrinet and
# was causing SimpleRock install to fail.  Moved 6.2.0-411 to bintray, pending investigation.

#yum_repository 'ntop' do
#  description 'ntop CentOS Repo'
#  baseurl 'http://packages.ntop.org/centos-stable/$releasever/$basearch/'
#  gpgcheck true
#  gpgkey 'http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri'
#  action :create
#end

#yum_repository 'ntop-noarch' do
#  description 'ntop CentOS Repo - noarch'
#  baseurl 'http://packages.ntop.org/centos-stable/$releasever/noarch/'
#  gpgcheck true
#  gpgkey 'http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri'
#  action :create
#end

execute 'import_ntop_key' do
  command 'rpm --import http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri'
end

#######################################################
################## Build YUM Cache ####################
#######################################################
execute 'yum_makecache' do
  command 'yum makecache fast'
end

#######################################################
################## Schwack Packages ###################
#######################################################
package 'firewalld' do
  action :remove
end

package 'postfix' do
  action :remove
end

#######################################################
############### Install Core Packages #################
#######################################################
#Pinning the ES version until v5 comes out.


yum_package 'bro' do
  version '2.4.1-1.1'
  allow_downgrade true
end

package ['tcpreplay', 'iptables-services', 'dkms', 'broctl', 'kafka-bro-plugin', 'gperftools-libs', 'git', 'java-1.8.0-oracle', 'kafka',  'jq', 'policycoreutils-python', 'patch', 'vim', 'openssl-devel', 'zlib-devel', 'net-tools', 'lsof', 'htop', 'GeoIP-update', 'GeoIP-devel', 'GeoIP', 'kafkacat', 'stenographer', 'bats', 'nmap-ncat', 'snort', 'daq', 'perl-libwww-perl', 'perl-Crypt-SSLeay', 'perl-Archive-Tar', 'perl-Sys-Syslog', 'perl-LWP-Protocol-https']

######################################################
################## Configure PF_RING #################
######################################################
#The damn ntop RPM doesn't create the config directory structure.
directory '/etc/pf_ring' do
  owner 'root'
  group 'root'
  mode '0755'
  action :create
end

# Enable PF_RING
file '/etc/pf_ring/pf_ring.start' do
  action :create
end

template '/etc/pf_ring/pf_ring.conf' do
  source 'pf_ring.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

service 'pf_ring' do
  action [ :enable, :start ]
end

service 'cluster' do
  action :disable
end

######################################################
#################### Configure Bro ###################
######################################################
template '/etc/GeoIP.conf' do
  source 'GeoIP.conf.erb'
  notifies :run, "execute[run_geoipupdate]", :immediately
end

execute 'run_geoipupdate' do
  command '/usr/bin/geoipupdate'
  action :nothing
  notifies :run, "bash[link_geoip_files]", :immediately
end

bash 'link_geoip_files' do
  code <<-EOH
    ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
    ln -s /usr/share/GeoIP/GeoLiteCountry.dat /usr/share/GeoIP/GeoIPCountry.dat
    ln -s /usr/share/GeoIP/GeoLiteASNum.dat /usr/share/GeoIP/GeoIPASNum.dat
    ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat
 EOH
  action :nothing
end

#Create bro data directories.
%w{logs spool}.each do |dir|
  directory "/data/bro/#{dir}" do
    mode '0755'
    owner 'root'
    group 'root'
    action :create
    recursive true
  end
end

# Convenience for the wandering analyst
%w{logs spool}.each do |dir|
  directory "/opt/bro/#{dir}" do
    action :delete
    recursive true
  end
  link "/opt/bro/#{dir}" do
    to "/data/bro/#{dir}"
  end
end

#Start bro
execute 'start_bro' do
  command '/opt/bro/bin/broctl install; /opt/bro/bin/broctl check && /opt/bro/bin/broctl start'
  action :nothing
  notifies :write, "log[branding]", :delayed
end


# Add custom scripts dir and readme.
directory '/opt/bro/share/bro/site/scripts' do
  owner 'root'
  group 'root'
  mode '0755'
  action :create
end

template '/opt/bro/share/bro/site/scripts/readme.txt' do
  source 'bro_scripts_readme.txt.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# Setup broctl.cfg
template '/opt/bro/etc/broctl.cfg' do
  source 'broctl.cfg.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# Setup networks.cfg
template '/opt/bro/etc/networks.cfg' do
  source 'networks.cfg.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# Setup node.cfg
template '/opt/bro/etc/node.cfg' do
  action :nothing
  source 'node.cfg.erb'
  owner 'root'
  group 'root'
  mode '0644'
  notifies :run, "execute[start_bro]", :delayed
end

# Setup local.bro
template '/opt/bro/share/bro/site/local.bro' do
  source 'local.bro.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# ROCK Bro Scripts
git '/opt/bro/share/bro/site/scripts/rock' do
  repository 'https://github.com/mocyber/rock-scripts.git'
  revision 'master'
  action :sync
end

template '/etc/profile.d/bro.sh' do
  source 'bro.sh.erb'
end

# Set capabilities for bro
execute 'set capabilities on bro' do
  command '/usr/sbin/setcap cap_net_raw,cap_net_admin=eip $(readlink -f /opt/bro/bin/bro)'
  not_if '/usr/sbin/setcap -v -q cap_net_raw,cap_net_admin=eip $(readlink -f /opt/bro/bin/bro)'
end

execute 'set capabilities on capstats' do
  command '/usr/sbin/setcap cap_net_raw,cap_net_admin=eip $(readlink -f /opt/bro/bin/capstats)'
  not_if '/usr/sbin/setcap -v -q cap_net_raw,cap_net_admin=eip $(readlink -f /opt/bro/bin/capstats)'
end

######################################################
############### Reread Systemd Configs ###############
######################################################
execute 'reload_systemd' do
  command "systemctl daemon-reload"
  action :nothing
end

######################################################
################# Configure Zookeeper ################
######################################################
#Enable and start zookeeper
service 'zookeeper' do
  action [ :enable, :start ]
end

######################################################
################### Configure Kafka ##################
######################################################
execute 'create_bro_topic' do
  command 'sleep 10; /opt/kafka/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic bro_raw'
  action :nothing
end

execute 'set_kafka_retention' do
  command 'sed -i "s/log.retention.hours=168/log.retention.hours=1/" /opt/kafka/config/server.properties'
  not_if {File.readlines('/opt/kafka/config/server.properties').grep(/^log\.retention\.hours=1/).size > 0}
end

execute 'set_kafka_data_dir' do
  command 'sed -i "s|log.dirs=/tmp/kafka-logs|log.dirs=/data/kafka|g" /opt/kafka/config/server.properties'
  not_if {File.readlines('/opt/kafka/config/server.properties').grep(/^log\.dirs=\/data\/kafka/).size > 0}
end

directory '/data/kafka' do
  mode '0755'
  owner 'kafka'
  group 'kafka'
  action :create
end

#Enable and start kafka
service 'kafka' do
  action [ :enable, :start ]
  notifies :run, "execute[create_bro_topic]", :delayed
end





######################################################
############### Start/Stop/Status Scripts ############
######################################################
template '/usr/local/bin/rock_start' do
  source 'rock_start.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

template '/usr/local/bin/rock_stop' do
  source 'rock_stop.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

template '/usr/local/bin/rock_status' do
  source 'rock_status.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

######################################################
############### Service Mode Scripts #################
######################################################
template '/usr/local/bin/training_mode' do
  source 'training_mode.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

template '/usr/local/bin/service_mode' do
  source 'service_mode.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

######################################################
############### Configure Stenographer ###############
######################################################
template '/etc/stenographer/config' do
  source 'etc_stenographer_config.erb'
  action :nothing
end

directory '/data/stenographer' do
  mode '0755'
  owner 'stenographer'
  group 'stenographer'
  action :create
end

%w{index packets}.each do |dir|
  directory "/data/stenographer/#{dir}" do
    mode '0755'
    owner 'stenographer'
    group 'stenographer'
    action :create
    recursive true
  end
end

#Stenographer configured, but disabled by default.
service 'stenographer' do
  action :disable
end

######################################################
######################## NGINX #######################
######################################################
template '/etc/nginx/conf.d/rock.conf' do
  source 'rock.conf.erb'
end

template '/etc/nginx/nginx.conf' do
  source 'nginx.conf.erb'
end

file '/etc/nginx/conf.d/default.conf' do
  action :delete
end

file '/etc/nginx/conf.d/example_ssl.conf' do
  action :delete
end

execute 'enable_nginx_connect_selinux' do
  command 'setsebool -P httpd_can_network_connect 1'
  not_if 'getsebool httpd_can_network_connect | grep -q "on$"'
end

service 'nginx' do
  action [ :enable, :start ]
end

######################################################
######################## SNORT #######################
######################################################
# Temaplate in the various snort config files
template '/etc/sysconfig/snort' do
  source 'snort.erb'
  action :nothing
  notifies :run, "bash[run_pulledpork]", :immediately
end

template '/etc/snort/snort.conf' do
  source 'snort.conf.erb'
end

template '/usr/local/bin/snort_cleanup.sh' do
  source 'snort_cleanup.sh.erb'
  mode '0700'
  owner 'root'
  group 'root'
end

cron 'snort_cleanup' do
  minute '58'
  command "/usr/local/bin/snort_cleanup.sh > /var/log/snort_cleanup.log 2>&1"
end

template '/etc/snort/disablesid.conf' do
  source 'disablesid.conf.erb'
end

template '/etc/snort/pulledpork.conf' do
  source 'pulledpork.conf.erb'
end

# Set snort capabilities
execute 'set capabilities on snort' do
  command '/usr/sbin/setcap cap_net_raw,cap_net_admin=eip $(readlink -f /usr/sbin/snort)'
  not_if '/usr/sbin/setcap -v -q cap_net_raw,cap_net_admin=eip $(readlink -f /usr/sbin/snort)'
end

# Install pulledpork  !!!TODO!!! pulledpork should probably be moved to /opt/pulledpork for consistency
git '/usr/local/pulledpork' do
  repository 'https://github.com/shirkdog/pulledpork.git'
  revision 'master'
  action :sync
end

file '/usr/local/pulledpork/pulledpork.pl' do
  mode '0755'
end

#`ln -s /usr/local/pulledpork/pulledpork.pl /usr/local/bin/pulledpork.pl`
link '/usr/local/bin/pulledpork.pl' do
  to '/usr/local/pulledpork/pulledpork.pl'
end

#`mkdir /usr/lib/snort_dynamicrules/; chmod 755 /usr/lib/snort_dynamicrules/; chown root:root /usr/lib/snort_dynamicrules/`
directory '/usr/lib/snort_dynamicrules' do
  mode '0755'
  owner 'root'
  group 'root'
  action :create
end

#`mkdir /etc/snort/rules/iplists`
directory '/etc/snort/rules/iplists' do
  mode '0755'
  owner 'root'
  group 'root'
  action :create
end

#`touch /etc/snort/rules/local.rules`
file '/etc/snort/rules/local.rules' do
  action :create
end

#`touch /etc/snort/rules/{black,white}_list.rules`
file '/etc/snort/rules/white_list.rules' do
  action :create
end

file '/etc/snort/rules/black_list.rules' do
  action :create
end

#`mkdir /data/snort; chown snort:snort /data/snort`
directory '/data/snort' do
  mode '0755'
  owner 'snort'
  group 'snort'
  action :create
end

directory '/data/snort/OLD' do
  mode '0755'
  owner 'snort'
  group 'snort'
  action :create
end

execute 'snort_chcon' do
  command 'chcon -v --type=snort_log_t /data/snort/'
  not_if 'ls -Zd /data/snort | grep -q snort_log_t'
end

# Run pulledpork
bash 'run_pulledpork' do
  code <<-EOH
  /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l;
  /usr/bin/systemctl restart snortd
  EOH
  action :nothing
end

# Add pulledpork cron
cron 'pulledpork' do
  hour '12'
  minute '0'
  command "/usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l > /var/log/snort/pulledpork.log 2>&1 && /usr/bin/systemctl restart snortd"
end

# To be continued
