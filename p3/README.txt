

description:
In our design, Blaster has a pending list, which contains queue of packets of current round to be sent, and an Acked set, which keeps track of seq# of acked packets.

When coarse timeout happens, blaster will clear pending list, load packets into pending list by differing Acked set and sliding window in ascending seq# order, and send first packet in pending list, set coarse-timeout boundary, then get into next step by waiting. 

When blaster receives an ACK packet, there are three cases that could happen:
1) it is already in Acked set, blaster will just ignore it
2) it is not LHS, seq# will be just added into Acked set
3) it is LHS, blaster will move window and add new packets into pending list

