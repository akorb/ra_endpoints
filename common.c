#include "common.h"
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

int receivePacket(packet_t *buffer, int socketfd, enum Level expectedPacketType)
{
    ssize_t received = recv(socketfd, buffer, sizeof(packet_t), 0);
    if (received < sizeof(packet_t))
    {
        printf("Received too small packet\n");
        return 1;
    }
    if (received == -1)
    {
        perror("recv");
        return 1;
    }
    if (buffer->packetType != expectedPacketType)
    {
        printf("Expected packet type %d but got %d\n", expectedPacketType, buffer->packetType);
        return 1;
    }

    return 0;
}

void bytesToHexString(char *target, const size_t targetLength, const uint8_t *bytes, const size_t bytesLength)
{
    // + 1 for null terminator
    if (targetLength < bytesLength * 2 + 1)
    {
        errx(1, "%s:%d: Provided buffer too short.\n", __func__, __LINE__);
    }

    for (int i = 0; i < bytesLength; i++)
    {
        int res = snprintf(target, 3, "%02hhx", bytes[i]);
        target += res;
    }
}

int sendPacket(int socketFd, packet_t *buffer)
{
    if (send(socketFd, buffer, sizeof(packet_t), 0) == -1)
    {
        perror("send");
        return 1;
    }
    return 0;
}

int executeCommand(const char *command)
{
    printf("Execute %s\n", command);
    return system(command);
}
