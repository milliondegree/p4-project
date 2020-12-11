#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

# Key part, rules writing function
def writeTunnelRules(p4info_helper, ingress_sw, egress_sw, tunnel_id,
                     dst_eth_addr, dst_ip_addr, sw_to_sw_port, sw_to_host_port):
    # 1) Tunnel Ingress Rule 
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.myTunnel_ingress",
        action_params={
            "dst_id": tunnel_id,
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed ingress tunnel rule on %s" % ingress_sw.name, "match-dstAddr:", dst_ip_addr, "action-dst_id:", tunnel_id)

    # 2) Tunnel Forwarding Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_forward",
        action_params={
            "port": sw_to_sw_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed tunnel forwarding rule on %s" % ingress_sw.name, "match-dst_id:", tunnel_id, "action-prot: ", sw_to_sw_port)

    # 3) Tunnel Egress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": sw_to_host_port
        })
    egress_sw.WriteTableEntry(table_entry)
    print("Installed egress tunnel rule on %s" % egress_sw.name, "match-dst_id:", tunnel_id, "action-dstAddr:", dst_eth_addr, "action-port:", sw_to_host_port)

# Call the rules writing function
def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Create a switch connection object for s1 and s2;
    # Also, dump all P4Runtime messages sent to switch to given txt files.
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='logs/s1-p4runtime-requests.txt')
    s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s2',
        address='127.0.0.1:50052',
        device_id=1,
        proto_dump_file='logs/s2-p4runtime-requests.txt')

    # Send master arbitration update message to establish this controller as master 
    # (required by P4Runtime before performing any other write operation)
    s1.MasterArbitrationUpdate()
    s2.MasterArbitrationUpdate()

    # Install the P4 program on the switches
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                    bmv2_json_file_path=bmv2_file_path)
    print("Installed P4 Program using SetForwardingPipelineConfig on s1")
    s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                    bmv2_json_file_path=bmv2_file_path)
    print("Installed P4 Program using SetForwardingPipelineConfig on s2")

    # Write the rules that tunnel traffic from h1 to h2
    writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=2,
                        dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2", sw_to_sw_port=2, sw_to_host_port=1)

    # Write the rules that tunnel traffic from h2 to h1
    writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=1,
                        dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1", sw_to_sw_port=2, sw_to_host_port=1)

    # ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    main(args.p4info, args.bmv2_json)