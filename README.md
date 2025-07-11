# Sniffer
A simple sniffer, parsing data just like wireshark does

Voici un README complet, structuré, bilingue (🇫🇷 Français + 🇬🇧 English), prêt à être ajouté à ton projet packet_sniffer :
📡 Packet Sniffer – Projet en C++ / C bas niveau
🇫🇷 Description

Ce projet est un analyseur de paquets réseau (sniffer), développé en C++ (avec des éléments C). Il capture les paquets transitant par une interface réseau, en mode standard ou promiscuité, et extrait des informations détaillées sur les couches Ethernet, IP, TCP/UDP, et HTTP.
🇫🇷 Fonctionnalités

    - Capture de paquets au niveau Ethernet (AF_PACKET)

    - Analyse Ethernet, IPv4, TCP, UDP

    - Détection et parsing HTTP

    - Capture en mode infini ou limité par nombre de paquets

    - Affichage lisible des payloads en ASCII et hexadécimal

    - Mode promiscuité (pour sniffer tout le trafic)

    - Sélection de l’interface réseau par argument

🇫🇷 Utilisation

./sniffer [OPTIONS]

Options disponibles :

--help                 Affiche l’aide
--count N              Capture N paquets
--infinite             Mode capture infini (CTRL+C pour arrêter)
--interface <name>     Spécifie une interface (ex: eth0, enp3s0, wlan0)
--promisc              Active le mode promiscuité
--http                 Active la détection/parsing HTTP

Exemple :

sudo ./sniffer --interface enp3s0 --count 20 --http --promisc

🇫🇷 Dépendances

Aucune bibliothèque externe. Utilise les headers système standards :

    <sys/socket.h>

    <linux/if_packet.h>

    <netinet/ip.h>

    <net/if.h>

    <sys/ioctl.h>

    <ifaddrs.h>

🇫🇷 Compilation
Avec make :

make

Fichier Makefile :

CXX = g++
CXXFLAGS = -Wall -O2

SRCS = main.cpp packet_reader.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET)
🇬🇧 Description

This project is a packet sniffer written in low-level C++/C. It captures raw Ethernet traffic on a given interface and extracts structured information from Ethernet, IP, TCP, UDP and HTTP packets.
🇬🇧 Features

    - Packet capture at Ethernet level using AF_PACKET

    - Ethernet, IPv4, TCP, UDP decoding

    - HTTP detection and parsing

    - Supports finite or infinite packet capture

    - Hex + ASCII payload dump

    - Promiscuous mode support

    - Custom interface selection

🇬🇧 Usage

./sniffer [OPTIONS]

Available options:

--help                 Display manual
--count N              Capture N packets
--infinite             Infinite capture (CTRL+C to stop)
--interface <name>     Choose a specific interface
--promisc              Enable promiscuous mode
--http                 Enable HTTP detection

Example:

sudo ./sniffer --interface enp3s0 --count 20 --http --promisc

🇬🇧 Dependencies

Uses only standard POSIX headers (no external libraries):

    <sys/socket.h>

    <linux/if_packet.h>

    <netinet/ip.h>

    <net/if.h>

    <sys/ioctl.h>

    <ifaddrs.h>

🇬🇧 Build
Using make:

make


 
