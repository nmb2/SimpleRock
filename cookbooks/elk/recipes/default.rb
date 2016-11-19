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
############### Install Elastic Repos #################
#######################################################
yum_repository 'logstash-2.4.x' do
  description 'Logstash repository for 2.4 packages'
  baseurl 'http://packages.elastic.co/logstash/2.4/centos'
  gpgcheck true
  gpgkey 'http://packages.elastic.co/GPG-KEY-elasticsearch'
  action :create
end

yum_repository 'elasticsearch-2.x' do
  description 'Elasticsearch repository for 2.x packages'
  baseurl 'http://packages.elastic.co/elasticsearch/2.x/centos'
  gpgcheck true
  gpgkey 'http://packages.elastic.co/GPG-KEY-elasticsearch'
  action :create
end

yum_repository 'kibana-4.6' do
  description 'Kibana repository for 4.6 packages'
  baseurl 'https://packages.elastic.co/kibana/4.6/centos'
  gpgcheck true
  gpgkey 'http://packages.elastic.co/GPG-KEY-elasticsearch'
  action :create
end


#######################################################
############### Install Core Packages #################
#######################################################
#Pinning the ES version until v5 comes out.
yum_package 'elasticsearch' do
  version '2.4.0-1'
  allow_downgrade true
end



package ['logstash', 'nginx', 'java-1.8.0-oracle', 'kibana']


######################################################
################ Configure Elasticsearch #############
######################################################
#Create Data Directory
directory '/data/elasticsearch' do
  mode '0755'
  owner 'elasticsearch'
  group 'elasticsearch'
  action :create
end

template '/etc/sysconfig/elasticsearch' do
  source 'sysconfig_elasticsearch.erb'
end

template '/usr/lib/sysctl.d/elasticsearch.conf' do
  source 'sysctl.d_elasticsearch.conf.erb'
end

template '/etc/elasticsearch/elasticsearch.yml' do
  source 'etc_elasticsearch.yml.erb'
end

template '/etc/security/limits.d/elasticsearch.conf' do
  source 'etc_limits.d_elasticsearch.conf.erb'
end

template '/usr/local/bin/es_cleanup.sh' do
  source 'es_cleanup.sh.erb'
  mode '0755'
end

execute 'set_es_memlock' do
  command 'sed -i "s/.*LimitMEMLOCK.*/LimitMEMLOCK=infinity/g" /usr/lib/systemd/system/elasticsearch.service'
  not_if {File.readlines('/usr/lib/systemd/system/elasticsearch.service').grep(/^LimitMEMLOCK=infinity/).size > 0}
end

service 'elasticsearch' do
  action [ :enable, :start ]
end

######################################################
################## Configure Logstash ################
######################################################
execute 'set_logstash_ipv4_affinity' do
  command 'echo  "LS_JAVA_OPTS=\"-Djava.net.preferIPv4Stack=true\"" >> /etc/sysconfig/logstash'
  not_if {File.readlines('/usr/lib/systemd/system/elasticsearch.service').grep(/^LS_JAVA_OPTS="-Djava.net.preferIPv4Stack=true"/).size > 0}
end

template '/etc/logstash/conf.d/kafka-bro.conf' do
  source 'kafka-bro.conf.erb'
end

service 'logstash' do
  action [ :enable, :start ]
end

######################################################
################## Configure Kibana ##################
######################################################
service 'kibana' do
  action [ :enable, :start ]
end

bash 'set_kibana_replicas' do
  code <<-EOH
  local ctr=0
  while ! $(ss -lnt | grep -q ':9200'); do sleep 1; ctr=$(expr $ctr + 1); if [ $ctr -gt 30 ]; then exit; fi; done
  curl -XPUT localhost:9200/_template/kibana-config -d ' {
   "order" : 0,
   "template" : ".kibana",
   "settings" : {
     "index.number_of_replicas" : "0",
     "index.number_of_shards" : "1"
   },
   "mappings" : { },
   "aliases" : { }
  }'
 EOH
end

# set logstash template for resp_location
execute 'logstash template' do
command %q^ curl -XPUT http://localhost:9200/_template/logstash  -d '
{"template":"logstash-*","settings":{"index":{"refresh_interval":"5s"}},"mappings":{"_default_":{"dynamic_templates":[{"message_field":{"mapping":{"fielddata":{"format":"disabled"},"index":"analyzed","omit_norms":true,"type":"string"},"match_mapping_type":"string","match":"message"}},{"string_fields":{"mapping":{"fielddata":{"format":"disabled"},"index":"analyzed","omit_norms":true,"type":"string","fields":{"raw":{"ignore_above":256,"index":"not_analyzed","type":"string"}}},"match_mapping_type":"string","match":"*"}}],"_all":{"omit_norms":true,"enabled":true},"properties":{"resp_location": {"type":"geo_point","index": "not_analyzed"},"@timestamp":{"type":"date"},"geoip":{"dynamic":true,"properties":{"ip":{"type":"ip"},"latitude":{"type":"float"},"location":{"type":"geo_point"},"longitude":{"type":"float"}}},"@version":{"index":"not_analyzed","type":"string"}}}},"aliases":{}}'^
end


######################################################
################ Configure ES Plugins ################
######################################################
require 'uri'

#license_plugin_url = 'https://download.elastic.co/elasticsearch/release/org/elasticsearch/plugin/license/2.3.2/license-2.3.2.zip'
#license_plugin_hash = 'd2df9e5b603a22d1ad903190eb1e9bfe3395837567c2713a7983d36cb0817202'
#marvel_agent_url = 'https://download.elastic.co/elasticsearch/release/org/elasticsearch/plugin/marvel-agent/2.3.2/marvel-agent-2.3.2.zip'
#marvel_agent_hash = 'c4c96434b775e016ee95210281efc4a0e7e4c68002282af87f3f9d83a18f64b8'
#esSQL_plugin_url = 'https://github.com/NLPchina/elasticsearch-sql/releases/download/2.3.2.0/elasticsearch-sql-2.3.2.0.zip'
#esSQL_plugin_hash = 'db15ec5ca36e1a3b0e8d4347e5d413ffb41a906d02b275e407a922f4cb2a69d0'
esHQ_plugin_url = 'https://codeload.github.com/royrusso/elasticsearch-HQ/legacy.zip/v2.0.3'
esHQ_plugin_hash = '1ddf966226f3424c5a4dd49583a3da476bba8885901f025e0a73dc9861bf8572'

#   Temporarily Removed
#   { :name => 'sql', :url => esSQL_plugin_url, :hash => esSQL_plugin_hash },
#   { :name => 'license', :url => license_plugin_url, :hash => license_plugin_hash },
#   { :name => 'marvel-agent', :url => marvel_agent_url, :hash => marvel_agent_hash },
[
  { :name => 'hq', :url => esHQ_plugin_url, :hash => esHQ_plugin_hash }
].each do |item|
  filename = File.basename(URI.parse(item[:url]).path)
  remote_file filename do
    source item[:url]
    checksum item[:hash]
    path File.join(Chef::Config['file_cache_path'], filename)
  end

  bash "install_#{filename}" do
    cwd '/usr/share/elasticsearch'
    code <<-EOH
      ./bin/plugin install file://#{File.join(Chef::Config['file_cache_path'], filename)}
    EOH
    not_if "/usr/share/elasticsearch/bin/plugin list | grep -q #{item[:name]}"
  end
end

# install elasticsearch license
bash 'es_license' do
  code <<-EOH
/usr/share/elasticsearch/bin/plugin install license
  EOH
 ignore_failure true
end

#install elasticsearch graph
bash 'es_graph' do
  code <<-EOH
/usr/share/elasticsearch/bin/plugin install graph
/opt/kibana/bin/kibana plugin --install elasticsearch/graph/latest
  EOH
 ignore_failure true
end

#install elasticsearch reporting
bash 'es_reporting' do
  code <<-EOH
/opt/kibana/bin/kibana plugin --install kibana/reporting/latest
  EOH
 ignore_failure true
end

#generate / insert encryption key
key = 'reporting.encryptionKey : "'+SecureRandom.hex+'"'

ruby_block "insert_encryptionkey" do
  block do
    file = Chef::Util::FileEdit.new("/opt/kibana/config/kibana.yml")
    file.insert_line_if_no_match("reporting.encryptionKey :", key)
    file.write_file
  end
end

bash 'es_postplugin_cleanup' do
  code <<-EOH
  /bin/systemctl daemon-reload
  /bin/systemctl restart elasticsearch
  /bin/systemctl restart kibana
  local ctr=0
  while ! $(ss -lnt | grep -q ':9200'); do sleep 1; ctr=$(expr $ctr + 1); if [ $ctr -gt 30 ]; then exit; fi; done
  /usr/local/bin/es_cleanup.sh
  EOH
end

#### Kibana plugins
##marvel_plugin_url = 'https://download.elasticsearch.org/elasticsearch/marvel/marvel-2.3.2.tar.gz'
##marvel_plugin_hash = '1736bf6facb25279ed9634004ab87d3b7c366b94d1ac9556f502c6cadbb48437'
##
##[
##  { :name => 'marvel', :url => marvel_plugin_url, :hash => marvel_plugin_hash }
##].each do |item|
##  filename = File.basename(URI.parse(item[:url]).path)
##  remote_file filename do
##    source item[:url]
##    checksum item[:hash]
##    path File.join(Chef::Config['file_cache_path'], filename)
##  end
##
##  bash "install_#{filename}" do
##    cwd '/opt/kibana'
##    code <<-EOH
##      ./bin/kibana plugin --install #{item[:name]} \
##      --url file://#{File.join(Chef::Config['file_cache_path'], filename)}
##    EOH
##    not_if { File.exist?("/opt/kibana/installedPlugins/#{item[:name]}")}
##    notifies :run, "bash[kibana_postplugin_cleanup]", :immediately
##  end
##end
##
##
##bash 'kibana_postplugin_cleanup' do
##  code <<-EOH
##  /bin/systemctl daemon-reload
##  /bin/systemctl restart kibana
##  /usr/bin/sleep 5
##  EOH
##end

#Offline Install
#bin/plugin install file:///path/to/file/license-2.1.0.zip
#bin/plugin install file:///path/to/file/marvel-agent-2.1.0.zip
#bin/kibana plugin --install marvel --url file:///path/to/file/marvel-2.1.0.tar.gz

######################################################
#################### Configure Cron ##################
######################################################
cron 'es_cleanup_cron' do
  hour '0'
  minute '1'
  command '/usr/local/bin/es_cleanup.sh >/dev/null 2>&1'
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
