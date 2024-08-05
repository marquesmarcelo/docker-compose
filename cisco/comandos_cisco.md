# Lista de Comandos IOS Cisco

Arquitetura Safe: https://community.cisco.com/t5/blogues-de-seguran%C3%A7a/o-que-%C3%A9-cisco-safe/ba-p/4894976

## Cancelar um comando CISCO travado

```ios
Control Shift 6
```

## Desativar o spanning-tree

```ios
Switch> enable
Switch# config t
Switch(config-if)# no spanning-tree vlan 1

Switch(config-if)# spanning-tree vlan 1
```

## Mac Protect

```ios
Switch> enable
Switch# configure terminal
Switch(config)# interface Fa0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security violation restrict
Switch(config-if)# end
Switch# write memory

show port-security interface Fa0/1
```

## Limpar uma porta

```ios
Switch# clear mac address-table dynamic interface <interface-id>
Switch# configure terminal
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# shutdown
Switch(config-if)# no shutdown
Switch(config-if)# end
Switch# write memory

Switch> enable
Switch# show mac address-table interface GigabitEthernet0/1
```

## DHCP Snooping

```ios
Switch> enable
Switch# configure terminal
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip dhcp snooping trust
Switch(config-if)# exit
Switch(config)# end
Switch# write memory
```

## Criação de VLAN

```ios
Switch> enable
Switch# configure terminal
Switch(config)# vlan 10
Switch(config-vlan)# name MinhaVLAN
Switch(config-vlan)# exit
Switch(config)# interface range GigabitEthernet0/1, GigabitEthernet0/5
Switch(config-if-range)# switchport mode access
Switch(config-if-range)# switchport access vlan 10
Switch(config-if-range)# exit
Switch(config)# end
Switch# write memory

show vlan brief
show running-config interface GigabitEthernet0/1
show running-config interface GigabitEthernet0/5
```

## Configurar QoS

```ios
Switch> enable
Switch# configure terminal
Switch(config)# mls qos
Switch(config)# mls qos map cos-dscp 0 8 16 24 32 46 48 56
Switch(config)# class-map match-all VOICE
Switch(config-cmap)# match ip dscp ef
Switch(config-cmap)# exit
Switch(config)# policy-map PRIORITY-VOICE
Switch(config-pmap)# class VOICE
Switch(config-pmap-c)# priority
Switch(config-pmap-c)# exit
Switch(config-pmap)# exit
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# service-policy input PRIORITY-VOICE
Switch(config-if)# exit
Switch(config)# end
Switch# write memory
```

**Detalhamento do Comando**

CoS (Class of Service): CoS é um campo de 3 bits no cabeçalho 802.1p, que permite classificar e priorizar o tráfego Ethernet em 8 níveis diferentes, variando de 0 a 7.

DSCP (Differentiated Services Code Point): DSCP é um campo de 6 bits no cabeçalho IP que permite classificar e priorizar o tráfego IP em 64 níveis diferentes, variando de 0 a 63.

CoS 0 é mapeado para DSCP 0

CoS 1 é mapeado para DSCP 8

CoS 2 é mapeado para DSCP 16

CoS 3 é mapeado para DSCP 24

CoS 4 é mapeado para DSCP 32

CoS 5 é mapeado para DSCP 46

CoS 6 é mapeado para DSCP 48

CoS 7 é mapeado para DSCP 56

Explicação dos Valores

CoS 0 a DSCP 0: Tráfego de melhor esforço (Best Effort).

CoS 1 a DSCP 8: Tráfego de prioridade baixa (Background).

CoS 2 a DSCP 16: Tráfego de prioridade média (Spare).

CoS 3 a DSCP 24: Tráfego de prioridade alta (Excellent Effort).

CoS 4 a DSCP 32: Tráfego de prioridade crítica (Critical Applications).

CoS 5 a DSCP 46: Tráfego de voz (Voice), alta prioridade com baixa latência.

CoS 6 a DSCP 48: Tráfego de controle de rede (Network Control), usado para protocolos de roteamento e outros controles de rede essenciais.

CoS 7 a DSCP 56: Tráfego de controle de rede (Network Control), máxima prioridade.

Exemplo Usando tc no Linux para alterar o Cos de todos os pacotes

No Linux, você pode usar o tc (Traffic Control) para marcar pacotes com um valor de CoS específico. Aqui está um exemplo de como fazer isso:

Instale o tc:

```bash
sudo apt-get install iproute2
```

Configurar a Marcação de CoS:

```bash
sudo tc qdisc add dev eth0 root handle 1: prio
sudo tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src 0/0 flowid 1:1 action skbedit priority 5
```

Substitua eth0 pelo nome da sua interface de rede e priority 5 pelo valor de CoS desejado (0 a 7).

# Roteamento sinkhole routing

Aqui está um exemplo completo de como configurar um roteador Cisco para redirecionar o tráfego destinado a uma rede específica para um endereço de sinkhole usando uma interface loopback:

```ios
Router> enable
Router# configure terminal
Router(config)# interface Loopback0
Router(config-if)# ip address 10.10.10.1 255.255.255.255
Router(config-if)# exit
Router(config)# ip route 192.168.10.0 255.255.255.0 10.10.10.1
Router(config)# end
Router# write memory
```