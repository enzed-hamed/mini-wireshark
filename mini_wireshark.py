#!/usr/bin/env python3


import socket
import struct
from tkinter import *
from tkinter import ttk
from tkinter import filedialog

# from tkinter import filedialog as fd


import textwrap
import binascii
import string
import random

import sys
import os
import threading

import time
import datetime


#     Pcap Global Header Format :
#                       ( magic number +
#                         major version number +
#                         minor version number +
#                         GMT to local correction +
#                         accuracy of timestamps +
#                         max length of captured #packets, in octets +
#                         data link type)
#
#

PCAP_GLOBAL_HEADER_FMT = "@ I H H i I I I "

# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

# Initialize pcap instance
pcap_obj = ""


class Pcap:
    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.file = filename
        self.pcap_file = open(self.file, "wb")  # 4 + 2 + 2 + 4 + 4 + 4 + 4
        self.pcap_file.write(
            struct.pack(
                "@ I H H i I I I ",
                PCAP_MAGICAL_NUMBER,
                PCAP_MJ_VERN_NUMBER,
                PCAP_MI_VERN_NUMBER,
                PCAP_LOCAL_CORECTIN,
                PCAP_ACCUR_TIMSTAMP,
                PCAP_MAX_LENGTH_CAP,
                link_type,
            )
        )

    def writelist(self, data=[]):
        for i in data:
            self.write(i)
        return

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split("."))
        length = len(data)
        self.pcap_file.write(struct.pack("@ I I I I", ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

    def del_file(self):
        os.remove(self.file)

    def save_file(self, new_filename):
        if ".pcap" not in new_filename:
            new_filename = new_filename + ".pcap"

        os.rename(self.file, new_filename)


root = Tk()
# Set window size
# root.geometry("1000x700")
root.geometry("1200x700")
# Set title
root.title("Packet Sniffer")
# Make window size fixed
root.resizable(False, False)
# Set root window color
root.config(background="#c4d1de")
# root.config(background="#d9d9da")
# root.config(background="#c9f1ed")
# root.config(background="#9eedfa")

# Initialize popup window variable
popup = ""

# Global var to switch off capture mode when encountered False value
capture = False


# Hooked with stop_bottom to stop capture
def stop_capture():
    # Control execution of packet capture through "capture" global variable
    global capture
    capture = False


def start_capture():
    if not capture:
        # threading.Thread(target=run).start()
        t = threading.Thread(target=run)
        t.start()


def save_file():
    # filename = filedialog.asksaveasfile(mode='w', defaultextension=".pcap")
    # if filename is None:  # asksaveasfile return `None` if dialog closed with "cancel".
    #     return
    stop_capture()
    try:
        if pcap_obj:
            filename = filedialog.asksaveasfilename(confirmoverwrite=False)
            pcap_obj.save_file(filename)
    except:
        pass


# Bottoms at the top
bottom_frame = Frame(root, background="#c4d1de")
bottom_frame.pack(side=TOP, fill=X)


start_bottom = Button(
    bottom_frame, width=5, height=3, text="Start", bg="#567", fg="White"
)
start_bottom.config(command=start_capture)
start_bottom.pack(side=LEFT, fill=X)
stop_bottom = Button(
    bottom_frame,
    width=5,
    height=3,
    command=stop_capture,
    text="Stop",
    bg="#567",
    fg="White",
)
stop_bottom.pack(side=LEFT, fill=X)
save_bottom = Button(
    bottom_frame,
    width=5,
    height=3,
    text="Save",
    bg="#567",
    fg="White",
    command=save_file,
)
save_bottom.pack(side=LEFT, fill=X)
# load_bottom = Button(bottom_frame, width=5, height=3, text="Load", bg='#567', fg='White')
# load_bottom.pack(side=LEFT, fill=X)

# Table label
table_frame = Frame(root)
table_frame.pack(side=BOTTOM, fill=BOTH, expand=2)

tree = ttk.Treeview(table_frame)
tree.pack(fill=BOTH, expand=2, side=LEFT)

# Scroll Bar
table_sb = Scrollbar(table_frame, orient=VERTICAL)
table_sb.pack(side=RIGHT, fill=Y)
tree.config(yscrollcommand=table_sb.set)
table_sb.config(command=tree.yview)

# Create an instance of Style widget
style = ttk.Style()
# Pick a theme
style.theme_use("default")
# Configure Treeview colors
style.configure(
    "Treeview",
    backgroud="silver",
    foreground="black",
    rowheight=25,
    fieldbackgrund="silver",
)
# style.map("Treeview", background=[("selected", "green")])
style.map("Treeview")

# Remove First empty column header
# tree['show'] = 'headings'
# Set columns
tree["columns"] = "no", "time", "src", "dst", "proto", "len", "info"
tree.column("#0", anchor=E, width=33)
tree.column("no", anchor=CENTER, width=81)
tree.column("time", anchor=CENTER, width=130)
tree.column("src", anchor=CENTER, width=90)
tree.column("dst", anchor=CENTER, width=90)
tree.column("proto", anchor=CENTER, width=55)
tree.column("len", anchor=CENTER, width=50)
tree.column("info", anchor=CENTER, width=100)
# Set column headings attr, eg. text
tree.heading("no", text="No.", anchor=CENTER)
tree.heading("time", text="Time", anchor=CENTER)
tree.heading("src", text="Source", anchor=CENTER)
tree.heading("dst", text="Destination", anchor=CENTER)
tree.heading("proto", text="Protocol", anchor=CENTER)
tree.heading("len", text="Length", anchor=CENTER)
tree.heading("info", text="Info", anchor=CENTER)


def run():
    def printPacketsV4(filter, data, raw_data):
        global pcap_obj

        (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

        # Populate 'src', 'dst' records in treeview
        tree.set(nom, "src", src)
        tree.set(nom, "dst", target)

        # Insert IP sub-item
        tree.insert(
            parent=nom,
            index=END,
            iid=nom + "_ip",
            text="    Internet",
            values=(
                "Protocol Version 4,      ",
                "Src: {},".format(src),
                "Dst: {}".format(target),
            ),
        )
        # Insert second layer sub-items
        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_version",
            values=("Version:", "4"),
        )
        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_header_len",
            values=("Header Length:", "{} bytes".format(header_length)),
        )

        # Calculate and add ip packet length
        hexvalue = binascii.hexlify(data).decode()
        packet_length = len([hexvalue[i : i + 2] for i in range(0, len(hexvalue), 2)])
        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_packet_len",
            values=("Total Length:", "{} bytes".format(packet_length)),
        )

        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_ttl",
            values=("Time to Live (TTL):", "{}".format(ttl)),
        )

        # ICMP
        if proto == 1 and (len(filter) == 0 or filter[1] == 1):
            icmp_type, code, checksum, data = icmp_packet(data)

            # Second layer sub-item
            tree.insert(
                parent=nom + "_ip",
                index=END,
                iid=nom + "_ip_proto",
                values=("Protocol:", "ICMP"),
            )

            # Set treeview "protocol"
            tree.set(nom, "proto", "ICMP")

            # Sub-item for icmp
            tree.insert(
                parent=nom,
                index=END,
                iid=nom + "_icmp",
                text="Internet",
                values=(
                    "Control Message Protocol",
                    "ocol                                                 ",
                ),
            )

            # Calculate and add icmp data length
            hexvalue = binascii.hexlify(data).decode()
            icmp_data_len = len(
                [hexvalue[i : i + 2] for i in range(0, len(hexvalue), 2)]
            )

            # Second layer sub-item for icmp
            tree.insert(
                parent=nom + "_icmp",
                index=END,
                iid=nom + "_icmp_type",
                values=("Type:", icmp_type),
            )
            tree.insert(
                parent=nom + "_icmp",
                index=END,
                iid=nom + "_icmp_code",
                values=("Code:", code),
            )
            tree.insert(
                parent=nom + "_icmp",
                index=END,
                iid=nom + "_icmp_sum",
                values=("Checksum:", checksum),
            )
            tree.insert(
                parent=nom + "_icmp",
                index=END,
                iid=nom + "_icmp_len",
                values=("Length:", icmp_data_len),
            )

        # TCP
        elif proto == 6 and (len(filter) == 0 or filter[1] == 6):
            (
                src_port,
                dest_port,
                sequence,
                acknowledgment,
                flag_urg,
                flag_ack,
                flag_psh,
                flag_rst,
                flag_syn,
                flag_fin,
            ) = struct.unpack("! H H L L H H H H H H", raw_data[:24])
            _, _, _, _, _, _, _, _, _, _, tcp_seg_data = tcp_seg(raw_data)
            # Calculate and add ip packet length
            hexvalue = binascii.hexlify(tcp_seg_data).decode()
            tcp_seg_len = len([hexvalue[i : i + 2] for i in range(0, len(hexvalue), 2)])

            # Set treeview "protocol"
            tree.set(nom, "proto", "TCP")
            tree.set(nom, "info", "{} -> {}".format(src_port, dest_port))

            # Insert TCP Sub-item
            tree.insert(
                parent=nom,
                index=END,
                iid=nom + "_tcp",
                text=" Transmis",
                values=(
                    "sion Control Protocol,         ",
                    "Src Port: {},".format(src_port),
                    "Dst Port: {},".format(dest_port),
                    "Seq: {},".format(sequence),
                    "Ack: {},".format(acknowledgment),
                    "Len: {}".format(tcp_seg_len),
                ),
            )

            # Second layer TCP sub-item
            tree.insert(
                parent=nom + "_tcp",
                index=END,
                iid=nom + "_tcp_src",
                values=("Source Port:", src_port),
            )
            tree.insert(
                parent=nom + "_tcp",
                index=END,
                iid=nom + "_tcp_dst",
                values=("Destination Port:", dest_port),
            )
            tree.insert(
                parent=nom + "_tcp",
                index=END,
                iid=nom + "_tcp_seq",
                values=("Sequence Number:", sequence),
            )
            tree.insert(
                parent=nom + "_tcp",
                index=END,
                iid=nom + "_tcp_ack",
                values=("Ack Number:", acknowledgment),
            )
            tree.insert(
                parent=nom + "_tcp",
                index=END,
                iid=nom + "_tcp_flag",
                values=("Flags:",),
            )

            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_urg",
                values=("Urgent:", "Set" if flag_urg else "Not Set"),
            )

            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_ack",
                values=("Acknowledgment:", "Set" if flag_ack else "Not Set"),
            )
            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_psh",
                values=("Push:", "Set" if flag_psh else "Not Set"),
            )
            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_rst",
                values=("Reset:", "Set" if flag_rst else "Not Set"),
            )
            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_syn",
                values=("Syn:", "Set" if flag_syn else "Not Set"),
            )
            tree.insert(
                parent=nom + "_tcp_flag",
                index=END,
                iid=nom + "_tcp_flag_fin",
                values=("Fin:", "Set" if flag_fin else "Not Set"),
            )
            # flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

            # Second layer sub-item
            tree.insert(
                parent=nom + "_ip",
                index=END,
                iid=nom + "_ip_proto",
                values=("Protocol:", "TCP"),
            )

            if len(data) > 0:
                # HTTP
                if src_port == 80 or dest_port == 80:
                    # Set treeview "protocol"
                    tree.set(nom, "proto", "HTTP")

                    print(format_output_line("", data))
                else:
                    print("*****TCP Data*****")
                    print(format_output_line("", data))
        # UDP
        elif proto == 17 and (len(filter) == 0 or filter[1] == 17):
            src_port, dest_port, length, data = udp_seg(data)

            # Set treeview "protocol"
            tree.set(nom, "proto", "UDP")
            tree.set(nom, "info", "{} -> {}".format(src_port, dest_port))

            # Second layer sub-item
            tree.insert(
                parent=nom + "_ip",
                index=END,
                iid=nom + "_ip_proto",
                values=("Protocol:", "UDP"),
            )

            # Sub-item udp
            tree.insert(
                parent=nom,
                index=END,
                iid=nom + "_udp",
                text="User Data",
                values=(
                    "gram Protocol:                   ",
                    "Src Port: {},".format(src_port),
                    "Dst Port: {}".format(dest_port),
                ),
            )

            # Second layer sub-item udp
            tree.insert(
                parent=nom + "_udp",
                index=END,
                iid=nom + "_udp_src",
                values=("Source Port:", src_port),
            )
            tree.insert(
                parent=nom + "_udp",
                index=END,
                iid=nom + "_udp_dst",
                values=("Destination Port:", dest_port),
            )
            tree.insert(
                parent=nom + "_udp",
                index=END,
                iid=nom + "_udp_len",
                values=("Length:", length),
            )
            # tree.insert(parent=nom+"_udp", index=END, iid=nom+"_udp_payload")

        # Second layer sub-item
        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_src",
            values=("Source Address:", "{}".format(src)),
        )
        tree.insert(
            parent=nom + "_ip",
            index=END,
            iid=nom + "_ip_dst",
            values=("Destination Address:", "{}".format(target)),
        )

    def printPacketsV6(filter, nextProto, newPacket):
        global pcap_obj

        remainingPacket = ""

        if nextProto == "ICMPv6" and (len(filter) == 0 or filter[2] == "ICMPv6"):
            # Set treeview "protocol"
            tree.set(nom, "proto", "ICMPv6")

            remainingPacket = icmpv6Header(newPacket)
        elif nextProto == "TCP" and (len(filter) == 0 or filter[2] == "TCP"):
            # Set treeview "protocol"
            tree.set(nom, "proto", "TCP")

            remainingPacket = tcpHeader(newPacket)
        elif nextProto == "UDP" and (len(filter) == 0 or filter[2] == "UDP"):
            # Set treeview "protocol"
            tree.set(nom, "proto", "UDP")

            remainingPacket = udpHeader(newPacket)

        return remainingPacket

    def tcpHeader(newPacket):
        global pcap_obj

        # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
        packet = struct.unpack("!2H2I4H", newPacket[0:20])
        srcPort = packet[0]
        dstPort = packet[1]
        sqncNum = packet[2]
        acknNum = packet[3]
        dataOffset = packet[4] >> 12
        reserved = (packet[4] >> 6) & 0x003F
        tcpFlags = packet[4] & 0x003F
        urgFlag = tcpFlags & 0x0020
        ackFlag = tcpFlags & 0x0010
        pushFlag = tcpFlags & 0x0008
        resetFlag = tcpFlags & 0x0004
        synFlag = tcpFlags & 0x0002
        finFlag = tcpFlags & 0x0001
        window = packet[5]
        checkSum = packet[6]
        urgPntr = packet[7]

        tree.set(nom, "info", "{} -> {}".format(srcPort, dstPort))

        if urgFlag == 32:
            print("\tUrgent Flag: Set")
        if ackFlag == 16:
            print("\tAck Flag: Set")
        if pushFlag == 8:
            print("\tPush Flag: Set")
        if resetFlag == 4:
            print("\tReset Flag: Set")
        if synFlag == 2:
            print("\tSyn Flag: Set")
        if finFlag == True:
            print("\tFin Flag: Set")

        packet = packet[20:]
        return packet

    def udpHeader(newPacket):
        global pcap_obj

        packet = struct.unpack("!4H", newPacket[0:8])
        srcPort = packet[0]
        dstPort = packet[1]
        lenght = packet[2]
        checkSum = packet[3]

        tree.set(nom, "info", "{} -> {}".format(srcPort, dstPort))
        tree.set(nom, "lenght", lenght)

        packet = packet[8:]
        return packet

    def icmpv6Header(data):
        global pcap_obj

        ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
            ">BBH", data[:4]
        )

        data = data[4:]
        return data

    def nextHeader(ipv6_next_header):
        global pcap_obj

        if ipv6_next_header == 6:
            ipv6_next_header = "TCP"
        elif ipv6_next_header == 17:
            ipv6_next_header = "UDP"
        elif ipv6_next_header == 43:
            ipv6_next_header = "Routing"
        elif ipv6_next_header == 1:
            ipv6_next_header = "ICMP"
        elif ipv6_next_header == 58:
            ipv6_next_header = "ICMPv6"
        elif ipv6_next_header == 44:
            ipv6_next_header = "Fragment"
        elif ipv6_next_header == 0:
            ipv6_next_header = "HOPOPT"
        elif ipv6_next_header == 60:
            ipv6_next_header = "Destination"
        elif ipv6_next_header == 51:
            ipv6_next_header = "Authentication"
        elif ipv6_next_header == 50:
            ipv6_next_header = "Encapsuling"

        return ipv6_next_header

    def ipv6Header(data, filter):
        global pcap_obj

        (
            ipv6_first_word,
            ipv6_payload_legth,
            ipv6_next_header,
            ipv6_hoplimit,
        ) = struct.unpack(">IHBB", data[0:8])
        ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

        print("##################3 IPv6{}".format(ipv6_src_ip))
        print("##################3 IPv6{}".format(ipv6_dst_ip))
        tree.set(nom, "src", ipv6_src_ip)
        tree.set(nom, "dst", ipv6_dst_ip)

        bin(ipv6_first_word)
        "{0:b}".format(ipv6_first_word)
        version = ipv6_first_word >> 28
        traffic_class = ipv6_first_word >> 16
        traffic_class = int(traffic_class) & 4095
        flow_label = int(ipv6_first_word) & 65535

        ipv6_next_header = nextHeader(ipv6_next_header)
        data = data[40:]

        return data, ipv6_next_header

    # Unpack Ethernet Frame
    def ethernet_frame(data):
        global pcap_obj

        proto = ""
        IpHeader = struct.unpack("!6s6sH", data[0:14])
        dstMac = binascii.hexlify(IpHeader[0])
        srcMac = binascii.hexlify(IpHeader[1])
        protoType = IpHeader[2]
        nextProto = hex(protoType)

        # Set source and destination mac address
        # src_mac = ''
        # for i in range(0, len(srcMac.decode('ascii')), 2):
        #     portion = srcMac.decode('ascii')[i: i+2]
        #     src_mac = src_mac + ':' + portion
        # src_mac = src_mac.strip(':')

        src_mac = srcMac.decode("ascii")
        src_mac = ":".join([src_mac[i : i + 2] for i in range(0, len(src_mac), 2)])
        src_mac = src_mac.strip(":")

        dst_mac = dstMac.decode("ascii")
        dst_mac = ":".join([dst_mac[i : i + 2] for i in range(0, len(dst_mac), 2)])
        dst_mac = dst_mac.strip(":")

        tree.set(nom, "src", src_mac)
        tree.set(nom, "dst", dst_mac)

        # Insert "Ethernet" sub-item
        tree.insert(
            parent=nom,
            index=END,
            iid=nom + "_ethernet",
            text="Ethernet II,",
            values=("Src: {},".format(src_mac), "Dst: {},".format(dst_mac)),
        )
        # Insert Second layer sub-items
        tree.insert(
            parent=nom + "_ethernet",
            index=END,
            iid=nom + "_ethernet_src",
            values=("Source:", src_mac),
        )
        tree.insert(
            parent=nom + "_ethernet",
            index=END,
            iid=nom + "_ethernet_dst",
            values=("Destination:", dst_mac),
        )
        tree.insert(
            parent=nom + "_ethernet",
            index=END,
            iid=nom + "_ethernet_proto",
            values=("Type:",),
        )

        # ARP
        if protoType == 2054:
            tree.set(nom, "proto", "ARP")
            tree.set(nom + "_ethernet_proto", "time", "ARP")
            # SDRP
        elif protoType == 42:
            tree.set(nom, "proto", "SDRP")
            tree.set(nom + "_ethernet_proto", "time", "sdrp")
        else:
            tree.set(nom, "proto", protoType)
            tree.set(nom + "_ethernet_proto", "time", "pro")

        if nextProto == "0x800":
            proto = "IPV4"
            tree.set(nom + "_ethernet_proto", "time", "IPv4")
        elif nextProto == "0x86dd":
            tree.set(nom + "_ethernet_proto", "time", "IPv6")
            proto = "IPV6"

        data = data[14:]

        return dstMac, srcMac, proto, data

        # Format MAC Address

    # Unpack IPv4 Packets Recieved
    def ipv4_Packet(data):
        global pcap_obj

        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
        return (
            version,
            header_len,
            ttl,
            proto,
            ipv4(src),
            ipv4(target),
            data[header_len:],
        )

    # Returns Formatted IP Address
    def ipv4(addr):
        return ".".join(map(str, addr))

    # Unpacks for any ICMP Packet
    def icmp_packet(data):
        icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
        return icmp_type, code, checksum, data[4:]

    # Unpacks for any TCP Packet
    def tcp_seg(data):
        (
            src_port,
            dest_port,
            sequence,
            acknowledgement,
            offset_reserved_flag,
        ) = struct.unpack("! H H L L H", data[:14])
        offset = (offset_reserved_flag >> 12) * 4
        flag_urg = (offset_reserved_flag & 32) >> 5
        flag_ack = (offset_reserved_flag & 32) >> 4
        flag_psh = (offset_reserved_flag & 32) >> 3
        flag_rst = (offset_reserved_flag & 32) >> 2
        flag_syn = (offset_reserved_flag & 32) >> 1
        flag_fin = (offset_reserved_flag & 32) >> 1

        return (
            src_port,
            dest_port,
            sequence,
            acknowledgement,
            flag_urg,
            flag_ack,
            flag_psh,
            flag_rst,
            flag_syn,
            flag_fin,
            data[offset:],
        )

    # Unpacks for any UDP Packet
    def udp_seg(data):
        src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
        return src_port, dest_port, size, data[8:]

    # Formats the output line
    def format_output_line(prefix, string):
        size = 80
        size -= len(prefix)
        if isinstance(string, bytes):
            string = "".join(r"\x{:02x}".format(byte) for byte in string)
            if size % 2:
                size -= 1
                return "\n".join(
                    [prefix + line for line in textwrap.wrap(string, size)]
                )

    def purge_table():
        # global pcap_obj
        # popup.destroy()
        pcap_obj.del_file()
        for item in tree.get_children():
            tree.delete(item)
        run()

    def cancel():
        popup.destroy()

    def save():
        pass

    global pcap_obj
    global popup

    if tree.get_children():
        purge_table()
        # popup = Toplevel(root)
        # popup.config(background="#c4d1de")
        # popup.geometry("450x150")
        # message_frame = Frame(popup)
        # message_frame.config(background="#c4d1de")
        # message_frame.pack(fill=BOTH)
        # popup.title("Unsaved packets..")
        # message = """Do you want to save the captured packets before starting a new\ncapture?\nYour captured packets will be lost if you don't save them."""
        # label = Label(message_frame, text=message)
        # label.config(background="#c4d1de")
        # label.pack()
        # button_frame = Frame(popup)
        # button_frame.pack(fill=BOTH)
        # button_frame.config(background="#c4d1de")
        # save_b = Button(button_frame, command=save, text="Save")
        # save_b.pack(side=RIGHT)
        # continue_button = Button(button_frame, command=purge_table, text="Continue without Saving")
        # continue_button.pack(side=RIGHT)
        # cancel_button = Button(button_frame, command=cancel, text="Cancel")
        # cancel_button.pack(side=RIGHT)

    start_capture_time = time.time()

    # Create Socket
    if os.name == "nt":
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((input("[+] YOUR_INTERFACE : "), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        # conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    file_name = "".join(
        random.SystemRandom().choices(
            "".join(random.SystemRandom().choices(string.ascii_letters, k=5))
        )
    )
    file_name = ".{}.pcap".format(file_name)
    # Create Object
    pcap_obj = Pcap("temp.pcap")

    filters = (["ICMP", 1, "ICMPv6"], ["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        for f in filters:
            if sys.argv[1] == f[0]:
                filter = f

    # Control execution of packet capture through "capture" global variable
    global capture
    capture = True
    index = 0
    while capture:
        # Capture a packet up to specified buffer size (which is maximum size possible)
        raw_data = conn.recvfrom(65535)

        # Save captured packets into pcap file
        pcap_obj.write(raw_data[0])

        # flush data
        pcap_obj.pcap_file.flush()

        recv_pck_time = time.time()

        # Insert a row in treeview and id it with number of packet
        index += 1
        nom = str(index)
        if index % 2 == 0:
            tree.insert(parent="", index=END, iid=nom, tags="odd_row")
        else:
            tree.insert(parent="", index=END, iid=nom, tags="even_row")
        # Make rows "striped(two consecutive rows with different colors)"
        tree.tag_configure("even_row", background="lightblue")
        tree.tag_configure("odd_row", background="#F6FBE8")
        # tree.tag_configure("odd_row", background="#FEECC8")
        # tree.tag_configure("odd_row", background="#C1E1D2")
        # tree.tag_configure("odd_row", background="#FED9C9")
        # tree.tag_configure("odd_row", background="#")
        tree.set(nom, "no", nom)
        # Packet elapsed time
        elapse_time = recv_pck_time - start_capture_time

        tree.set(nom, "time", elapse_time)

        # Create Frame sub_item
        tree.insert(parent=nom, index=END, iid=nom + "_frame", text="Frame")
        tree.set(nom + "_frame", "no", "nom. {}:".format(nom))

        # Calculate and add frame length
        hexvalue = binascii.hexlify(raw_data[0]).decode()
        frame_length = len([hexvalue[i : i + 2] for i in range(0, len(hexvalue), 2)])
        tree.set(nom, "len", frame_length)

        # Set bytes on wire (like wireshark)
        bits = frame_length * 8
        tree.set(
            nom + "_frame",
            "time",
            "{} bytes on wire ({} bits)".format(frame_length, bits),
        )
        # Insert today date
        tree.insert(
            parent=nom + "_frame",
            index=END,
            iid=nom + "_frame_date",
            values=(
                "Arrival Time:",
                datetime.datetime.now().strftime("%b %d, %Y %H:%M:%f"),
            ),
        )

        # Create second layer sub-item
        tree.insert(
            parent=nom + "_frame",
            index=END,
            iid=nom + "_frame_byte",
            values=(
                "Frame Length:",
                "{} bytes ({} bits)".format(frame_length, bits),
            ),
        )

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data[0])

        if eth_proto == "IPV6":
            newPacket, nextProto = ipv6Header(data, filter)
            printPacketsV6(filter, nextProto, newPacket)

        elif eth_proto == "IPV4":
            printPacketsV4(filter, data, raw_data[0])

            # Close pcap file
    pcap_obj.close()


def on_close():
    global capture
    capture = False


root.protocol("VM_DELETE_WINDOW", on_close)
root.mainloop()
