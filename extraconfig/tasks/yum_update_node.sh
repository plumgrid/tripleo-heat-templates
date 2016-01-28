#!/bin/bash

# A script to manually update packages on RHEL-OSP cluster with PLUMgrid

echo "Started yum_update.sh on server $(hostname -f) at `date`"

# seconds to wait for this node to rejoin the cluster after update
cluster_start_timeout=600
galera_sync_timeout=360
cluster_settle_timeout=1800

command_arguments=${command_arguments:-}

list_updates=$(yum list updates)

if [[ "$list_updates" == "" ]]; then
    echo "No packages require updating"
    exit 0
fi

pacemaker_status=$(systemctl is-active pacemaker)
pacemaker_dumpfile=$(mktemp)

if [[ "$pacemaker_status" == "active" ]] ; then
SERVICES="memcached
httpd
neutron-server
openstack-ceilometer-alarm-evaluator
openstack-ceilometer-alarm-notifier
openstack-ceilometer-api
openstack-ceilometer-central
openstack-ceilometer-collector
openstack-ceilometer-notification
openstack-cinder-api
openstack-cinder-scheduler
openstack-cinder-volume
openstack-glance-api
openstack-glance-registry
openstack-heat-api
openstack-heat-api-cfn
openstack-heat-api-cloudwatch
openstack-heat-engine
openstack-keystone
openstack-nova-api
openstack-nova-conductor
openstack-nova-consoleauth
openstack-nova-novncproxy
openstack-nova-scheduler"

    echo "Dumping Pacemaker config"
    pcs cluster cib $pacemaker_dumpfile

    echo "Checking for missing constraints"

    if ! pcs constraint order show | grep "start openstack-nova-novncproxy-clone then start openstack-nova-api-clone"; then
        pcs -f $pacemaker_dumpfile constraint order start openstack-nova-novncproxy-clone then openstack-nova-api-clone
    fi

    if ! pcs constraint order show | grep "start rabbitmq-clone then start openstack-keystone-clone"; then
        pcs -f $pacemaker_dumpfile constraint order start rabbitmq-clone then openstack-keystone-clone
    fi

    if ! pcs constraint order show | grep "promote galera-master then start openstack-keystone-clone"; then
        pcs -f $pacemaker_dumpfile constraint order promote galera-master then openstack-keystone-clone
    fi

    if pcs resource | grep "haproxy-clone"; then
        SERVICES="$SERVICES haproxy"
        if ! pcs constraint order show | grep "start haproxy-clone then start openstack-keystone-clone"; then
            pcs -f $pacemaker_dumpfile constraint order start haproxy-clone then openstack-keystone-clone
        fi
    fi

    if ! pcs constraint order show | grep "start memcached-clone then start openstack-keystone-clone"; then
        pcs -f $pacemaker_dumpfile constraint order start memcached-clone then openstack-keystone-clone
    fi

    if ! pcs constraint order show | grep "promote redis-master then start openstack-ceilometer-central-clone"; then
        pcs -f $pacemaker_dumpfile constraint order promote redis-master then start openstack-ceilometer-central-clone require-all=false
    fi


    if ! pcs resource defaults | grep "resource-stickiness: INFINITY"; then
        pcs -f $pacemaker_dumpfile resource defaults resource-stickiness=INFINITY
    fi

    echo "Setting resource start/stop timeouts"
    for service in $SERVICES; do
        pcs -f $pacemaker_dumpfile resource update $service op start timeout=200s op stop timeout=200s
    done
    # mongod start timeout is higher, setting only stop timeout
    pcs -f $pacemaker_dumpfile resource update mongod op start timeout=370s op stop timeout=100s

    echo "Applying new Pacemaker config"
    pcs cluster cib-push $pacemaker_dumpfile

    echo "Pacemaker running, stopping cluster node and doing full package update"
    node_count=$(pcs status xml | grep -o "<nodes_configured.*/>" | grep -o 'number="[0-9]*"' | grep -o "[0-9]*")
    if [[ "$node_count" == "1" ]] ; then
        echo "Active node count is 1, stopping node with --force"
        pcs cluster stop --force
    else
        pcs cluster stop
    fi

    # clean leftover keepalived and radvd instances from neutron
    # (can be removed when we remove neutron-netns-cleanup from cluster services)
    # see https://review.gerrithub.io/#/c/248931/1/neutron-netns-cleanup.init
    killall neutron-keepalived-state-change 2>/dev/null || :
    kill $(ps ax | grep -e "keepalived.*\.pid-vrrp" | awk '{print $1}') 2>/dev/null || :
    kill $(ps ax | grep -e "radvd.*\.pid\.radvd" | awk '{print $1}') 2>/dev/null || :
fi

command=${command:-update}
full_command="yum -y $command $command_arguments"
echo "Running: $full_command"

result=$($full_command)
return_code=$?
echo "$result"
echo "yum return code: $return_code"

if [[ "$pacemaker_status" == "active" ]] ; then
    echo "Starting cluster node"
    pcs cluster start

    hostname=$(hostname -s)
    tstart=$(date +%s)
    while [[ "$(pcs status | grep "^Online" | grep -F -o $hostname)" == "" ]]; do
        sleep 5
        tnow=$(date +%s)
        if (( tnow-tstart > cluster_start_timeout )) ; then
            echo "ERROR $hostname failed to join cluster in $cluster_start_timeout seconds"
            pcs status
            exit 1
        fi
    done

    tstart=$(date +%s)
    while ! clustercheck; do
        sleep 5
        tnow=$(date +%s)
        if (( tnow-tstart > galera_sync_timeout )) ; then
            echo "ERROR galera sync timed out"
            exit 1
        fi
    done

    echo "Waiting for pacemaker cluster to settle"
    if ! timeout -k 10 $cluster_settle_timeout crm_resource --wait; then
        echo "ERROR timed out while waiting for the cluster to settle"
        exit 1
    fi

    pcs status

else
    echo -n "true" > $heat_outputs_path.update_managed_packages
fi

#Workarounds for SElinux issues
/sbin/restorecon -R /etc/neutron/ || true
/sbin/restorecon -R /usr/lib/python2.7/site-packages/ || true

echo "Finished yum_update.sh on server $deploy_server_id at `date`"

exit $return_code