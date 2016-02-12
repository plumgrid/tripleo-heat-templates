# Copyright 2014 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

include tripleo::packages

create_resources(sysctl::value, hiera('sysctl_settings'), {})

if count(hiera('ntp::servers')) > 0 {
  include ::ntp
}

file { ['/etc/libvirt/qemu/networks/autostart/default.xml',
        '/etc/libvirt/qemu/networks/default.xml']:
  ensure => absent,
  before => Service['libvirt']
}
# in case libvirt has been already running before the Puppet run, make
# sure the default network is destroyed
exec { 'libvirt-default-net-destroy':
  command => '/usr/bin/virsh net-destroy default',
  onlyif => '/usr/bin/virsh net-info default | /bin/grep -i "^active:\s*yes"',
  before => Service['libvirt'],
}

include ::nova
include ::nova::config
include ::nova::compute

nova_config {
  'DEFAULT/my_ip':                     value => $ipaddress;
  'DEFAULT/linuxnet_interface_driver': value => 'nova.network.linux_net.LinuxOVSInterfaceDriver';
}

$nova_enable_rbd_backend = hiera('nova_enable_rbd_backend', false)
if $nova_enable_rbd_backend {
  include ::ceph::profile::client

  $client_keys = hiera('ceph::profile::params::client_keys')
  $client_user = join(['client.', hiera('ceph_client_user_name')])
  class { '::nova::compute::rbd':
    libvirt_rbd_secret_key => $client_keys[$client_user]['secret'],
  }
}

if hiera('cinder_enable_nfs_backend', false) {
  if ($::selinux != "false") {
    selboolean { 'virt_use_nfs':
        value => on,
        persistent => true,
    } -> Package['nfs-utils']
  }

  package {'nfs-utils': } -> Service['nova-compute']
}

include ::nova::compute::libvirt
include ::nova::network::neutron
include ::neutron

if 'iovisor' in hiera('neutron_mechanism_drivers') {
   # forward all ipv4 traffic
   # this is required for the vms to pass through the gateways public interface
   sysctl::value { 'net.ipv4.ip_forward': value => '1' }

   # ifc_ctl_pp needs to be invoked by root as part of the vif.py when a VM is powered on
   file { '/etc/sudoers.d/ifc_ctl_sudoers':
     ensure  => file,
     owner   => root,
     group   => root,
     mode    => '0440',
     content => "nova ALL=(root) NOPASSWD: /opt/pg/bin/ifc_ctl_pp *\n",
   }
   
   file { '/etc/libvirt/qemu.conf':
     ensure  => file,
     owner   => root,
     group   => root,
     mode    => '0440',
     content => "cgroup_device_acl=[\"/dev/null\",\"/dev/full\",\"/dev/zero\",\"/dev/random\",\"/dev/urandom\",\"/dev/ptmx\",\"/dev/kvm\",\"/dev/kqemu\",\"/dev/rtc\",\"/dev/hpet\",\"/dev/net/tun\"]\nclear_emulator_capabilities=0\nuser=\"root\"\ngroup=\"root\"",
     notify => Service['libvirt']
   }
  
   class { '::nova::api':
     enabled  => false,
     neutron_metadata_proxy_shared_secret  => hiera(neutron_metadata_proxy_shared_secret),
     admin_password  => hiera(nova_password),
     auth_host  => hiera(nova_api_host),
     sync_db  => false, 
     before => Service['openstack-nova-metadata-api'],
   }
   
   service { 'openstack-nova-metadata-api':
    ensure => running,
    enable => true,
   }

   $check_director_ips = hiera(plumgrid_director_mgmt_ips, 'undef')
   if $check_director_ips == 'undef' {
     $plumgrid_director_ips = hiera(controller_node_ips)
   } else {
     $plumgrid_director_ips = hiera(plumgrid_director_mgmt_ips)
   }

   # Disable NetworkManager
   service { 'NetworkManager':
     ensure => stopped,
     enable => false,
   }
 
   # Install PLUMgrid Edge
    class{ 'plumgrid':
      plumgrid_ip => $plumgrid_director_ips,
      plumgrid_port => '8001',
      rest_port => '9180',
      mgmt_dev => hiera('plumgrid_mgmt_dev', '%AUTO_DEV%'),
      fabric_dev => hiera('plumgrid_fabric_dev', '%AUTO_DEV%'),
      repo_baseurl => hiera('plumgrid_repo_baseurl'), 
      lvm_keypath => '/var/lib/plumgrid/id_rsa.pub',
      md_ip => hiera('plumgrid_md_ip'),
      repo_component => hiera('plumgrid_repo_component'),
      source_net=> hiera('plumgrid_network', undef),
      dest_net => hiera('plumgrid_network', undef),
      manage_repo => true,
    }

    class { firewall: }
    
    firewall {'001 nova metdata incoming':
      proto  => 'tcp',
      dport  => ["8775"],
      action => 'accept',
    }    

} else {

  class { 'neutron::plugins::ml2':
    flat_networks        => split(hiera('neutron_flat_networks'), ','),
    tenant_network_types => [hiera('neutron_tenant_network_type')],
  }

  class { 'neutron::agents::ml2::ovs':
    bridge_mappings => split(hiera('neutron_bridge_mappings'), ','),
    tunnel_types    => split(hiera('neutron_tunnel_types'), ','),
  }

}

if 'cisco_n1kv' in hiera('neutron_mechanism_drivers') {
  class { 'neutron::agents::n1kv_vem':
    n1kv_source          => hiera('n1kv_vem_source', undef),
    n1kv_version         => hiera('n1kv_vem_version', undef),
  }
}


include ::ceilometer
include ::ceilometer::agent::compute
include ::ceilometer::agent::auth

$snmpd_user = hiera('snmpd_readonly_user_name')
snmp::snmpv3_user { $snmpd_user:
  authtype => 'MD5',
  authpass => hiera('snmpd_readonly_user_password'),
}
class { 'snmp':
  agentaddress => ['udp:161','udp6:[::1]:161'],
  snmpd_config => [ join(['rouser ', hiera('snmpd_readonly_user_name')]), 'proc  cron', 'includeAllDisks  10%', 'master agentx', 'trapsink localhost public', 'iquerySecName internalUser', 'rouser internalUser', 'defaultMonitors yes', 'linkUpDownNotifications yes' ],
}

package_manifest{'/var/lib/tripleo/installed-packages/overcloud_compute': ensure => present}
